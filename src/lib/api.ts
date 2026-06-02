import type { ChatMessage, HistoryComparison, HistoryEntry, IntelligenceReport } from './types'

export type ScanReport = IntelligenceReport

const API = '/api'

export type GuestMode = boolean

function headers(guest: GuestMode): HeadersInit {
  const h: Record<string, string> = { 'Content-Type': 'application/json' }
  if (guest) h['x-aegis-user'] = 'guest:local'
  const stored = localStorage.getItem('aegis-user-id')
  if (stored && !guest) h['x-aegis-user'] = stored
  return h
}

export async function checkHealth(): Promise<{ ok: boolean; openRouter: boolean; version?: string; pipeline?: string }> {
  try {
    const res = await fetch(`${API}/health`)
    return res.json()
  } catch {
    throw new Error('Cannot reach API server. Run npm run dev (web + API on port 8787).')
  }
}

export async function createScan(
  body: {
    title?: string
    targetUrl?: string
    appDescription?: string
    apiSpec?: string
    ctfDescription?: string
    authorized?: boolean
  },
  guest: boolean,
) {
  const res = await fetch(`${API}/scans`, { method: 'POST', headers: headers(guest), body: JSON.stringify(body) })
  const data = await res.json()
  if (!res.ok) throw new Error(data.error ?? 'Failed to create scan')
  return data as { id: string }
}

export async function startRun(scanId: string, guest: boolean) {
  const res = await fetch(`${API}/scans/${scanId}/run`, { method: 'POST', headers: headers(guest) })
  const data = await res.json()
  if (!res.ok) throw new Error(data.error ?? 'Failed to start scan')
  return data as { runId: string }
}

export type RunResponse = {
  run: { id: string; finished_at?: string | null; success?: boolean | null; total_steps: number }
  steps: { agent_name: string; step: number }[]
  report: ScanReport | null
  status: 'running' | 'completed' | 'failed'
  error: { code: string; message: string } | null
  upgradedFromLegacy?: boolean
}

export async function getRun(runId: string): Promise<RunResponse> {
  const res = await fetch(`${API}/runs/${runId}`)
  if (!res.ok) throw new Error('Run not found')
  return res.json()
}

export async function listScans(guest: boolean) {
  const res = await fetch(`${API}/scans`, { headers: headers(guest) })
  return res.json() as Promise<{
    challenges: unknown[]
    runs: { id: string; challenge_id: string; total_steps: number; success?: boolean; finished_at?: string }[]
  }>
}

export function subscribeRun(
  runId: string,
  onStep: (data: { agent: string; step: number }) => void,
  onDone: (data: { success?: boolean; error?: { message: string }; report?: ScanReport }) => void,
) {
  let finished = false
  let lastStep = 0

  const finish = (data: Parameters<typeof onDone>[0]) => {
    if (finished) return
    finished = true
    onDone(data)
    es.close()
    clearInterval(pollTimer)
  }

  const es = new EventSource(`${API}/runs/${runId}/stream`)

  es.addEventListener('step', (e) => {
    const s = JSON.parse((e as MessageEvent).data) as { agent: string; step: number }
    if (s.step > lastStep) {
      lastStep = s.step
      onStep(s)
    }
  })

  es.addEventListener('done', (e) => finish(JSON.parse((e as MessageEvent).data)))

  es.addEventListener('error', (e) => {
    try {
      const data = JSON.parse((e as MessageEvent).data)
      finish({ success: false, error: { message: data.message ?? 'Scan timed out' } })
    } catch {
      /* poll handles final state */
    }
  })

  const pollTimer = setInterval(async () => {
    if (finished) return
    try {
      const r = await getRun(runId)
      for (const s of r.steps) {
        if (s.step > lastStep && s.step < 900) {
          lastStep = s.step
          onStep({ agent: s.agent_name, step: s.step })
        }
      }
      if (r.status !== 'running') {
        finish({
          success: r.status === 'completed',
          error: r.error ? { message: r.error.message } : undefined,
          report: r.report ?? undefined,
        })
      }
    } catch {
      /* ignore transient poll errors */
    }
  }, 2000)

  return () => {
    finished = true
    es.close()
    clearInterval(pollTimer)
  }
}

export async function fetchHistory(guest: boolean) {
  const res = await fetch(`${API}/history`, { headers: headers(guest) })
  return res.json() as Promise<{ entries: HistoryEntry[]; comparison: HistoryComparison | null }>
}

export async function fetchChatHistory(runId: string) {
  const res = await fetch(`${API}/runs/${runId}/chat`)
  const data = await res.json()
  if (!res.ok) throw new Error(data.error ?? 'Failed to load chat')
  return data as { messages: ChatMessage[] }
}

export async function sendChatMessage(runId: string, message: string) {
  const res = await fetch(`${API}/runs/${runId}/chat`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...Object.fromEntries(Object.entries(headers(true))) },
    body: JSON.stringify({ message }),
  })
  const data = await res.json()
  if (!res.ok) throw new Error(data.error ?? 'Chat failed')
  return data as { reply: string; messages: ChatMessage[] }
}
