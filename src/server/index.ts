import './env'
import { Hono } from 'hono'
import { cors } from 'hono/cors'
import { createScan, executeRun, startRun } from '../lib/aegis/orchestrator'
import { hasOpenRouterKey, logOpenRouterKeyStatus } from '../lib/aegis/ai'
import { mapToAegisError } from '../lib/aegis/errors'
import { localStore } from '../lib/store'
import { upgradeLegacyReport } from '../lib/upgrade-legacy-report'
import { reconFromReport } from '../lib/aegis/recon-from-report'
import { applyPostureToReport, buildPlatformIntelligence } from '../lib/platform/build'
import { buildScanSignals, injectTransportFindings } from '../lib/platform/evidence-engine'
import { GUEST_USER_ID } from '../lib/types'

logOpenRouterKeyStatus()

const app = new Hono()
app.use('/*', cors({ origin: '*' }))

function resolveUserId(header?: string | null): string {
  if (header?.startsWith('guest:')) return GUEST_USER_ID
  return header || GUEST_USER_ID
}

app.get('/api/health', (c) =>
  c.json({
    ok: true,
    service: 'aegis-x',
    version: 'intelligence-1.0',
    pipeline: 'pentest → evidence → rules → threat → risk → roadmap',
    methodology: 'automated-pentest',
    openRouter: Boolean(process.env.OPENROUTER_API_KEY?.trim()),
    chatAvailable: Boolean(process.env.OPENROUTER_API_KEY?.trim()),
  }),
)

app.post('/api/scans', async (c) => {
  try {
    const body = await c.req.json<{
      title?: string
      targetUrl?: string
      appDescription?: string
      apiSpec?: string
      ctfDescription?: string
      authorized?: boolean
    }>()
    const userId = resolveUserId(c.req.header('x-aegis-user'))
    const id = createScan({
      userId,
      title: body.title ?? 'Security Scan',
      targetUrl: body.targetUrl,
      appDescription: body.appDescription,
      apiSpec: body.apiSpec,
      ctfDescription: body.ctfDescription,
      authorized: body.authorized,
    })
    return c.json({ id })
  } catch (err) {
    const e = mapToAegisError(err)
    return c.json({ error: e.userMessage, code: e.code }, 400)
  }
})

app.post('/api/scans/:id/run', async (c) => {
  const scanId = c.req.param('id')
  const userId = resolveUserId(c.req.header('x-aegis-user'))
  const runId = startRun(scanId, userId)
  executeRun(runId, userId).catch(() => {})
  return c.json({ runId })
})

app.post('/api/challenges', async (c) => {
  const body = await c.req.json<{ title: string; description: string; targetUrl?: string }>()
  const userId = resolveUserId(c.req.header('x-aegis-user'))
  const id = createScan({
    userId,
    title: body.title,
    targetUrl: body.targetUrl,
    appDescription: body.description,
  })
  return c.json({ id })
})

app.post('/api/challenges/:id/run', async (c) => {
  const challengeId = c.req.param('id')
  const userId = resolveUserId(c.req.header('x-aegis-user'))
  const runId = startRun(challengeId, userId)
  executeRun(runId, userId).catch(() => {})
  return c.json({ runId })
})

function resolveReport(runId: string) {
  const data = localStore.read()
  const run = data.runs.find((r) => r.id === runId)
  if (!run) return null
  const raw = data.scan_results.find((s) => s.run_id === runId)?.report ?? null
  const challenge = data.challenges.find((c) => c.id === run.challenge_id)
  const upgraded = raw
    ? upgradeLegacyReport(raw, {
        targetUrl: challenge?.target_url ?? undefined,
        targetTitle: challenge?.title,
      })
    : null
  if (upgraded && (!upgraded.platform?.evidenceCoverage || !upgraded.platform?.findings?.length)) {
    let recon = reconFromReport(upgraded)
    const signals = buildScanSignals(recon, { targetUrl: challenge?.target_url })
    recon = injectTransportFindings(recon, signals)
    const platform = buildPlatformIntelligence(upgraded, recon, { headersSummary: undefined })
    Object.assign(upgraded, applyPostureToReport(upgraded, platform))
  }

  const wasLegacy = !!(upgraded && raw && !('platform' in raw))
  if (wasLegacy && upgraded) {
    localStore.write((d) => {
      const idx = d.scan_results.findIndex((s) => s.run_id === runId)
      if (idx >= 0) d.scan_results[idx] = { run_id: runId, report: upgraded }
    })
  }
  return {
    run,
    report: upgraded,
    wasLegacy,
    steps: data.agent_steps.filter((s) => s.run_id === runId && s.step < 900).sort((a, b) => a.step - b.step),
  }
}

app.get('/api/runs/:runId', (c) => {
  const runId = c.req.param('runId')
  const resolved = resolveReport(runId)
  if (!resolved) return c.json({ error: 'not found' }, 404)
  const { run, report, steps } = resolved
  return c.json({
    run,
    steps,
    report,
    upgradedFromLegacy: resolved.wasLegacy,
    status: run.finished_at ? (run.success ? 'completed' : 'failed') : 'running',
    error: run.error_message ? { code: run.error_code, message: run.error_message } : null,
  })
})

app.get('/api/runs/:runId/stream', (c) => {
  const runId = c.req.param('runId')
  let cursor = 0

  const stream = new ReadableStream({
    async start(controller) {
      const encoder = new TextEncoder()
      const send = (event: string, data: unknown) => {
        controller.enqueue(encoder.encode(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`))
      }

      for (let i = 0; i < 180; i++) {
        const data = localStore.read()
        const run = data.runs.find((r) => r.id === runId)
        const steps = data.agent_steps.filter((s) => s.run_id === runId && s.step > cursor && s.step < 900)
        for (const s of steps.sort((a, b) => a.step - b.step)) {
          cursor = s.step
          send('step', { agent: s.agent_name, step: s.step })
        }
        if (run?.finished_at) {
          const resolved = resolveReport(runId)
          send('done', {
            runId,
            success: run.success,
            error: run.error_message ? { code: run.error_code, message: run.error_message } : null,
            report: resolved?.report ?? null,
          })
          controller.close()
          return
        }
        await new Promise((r) => setTimeout(r, 500))
      }
      send('error', { message: 'Scan timed out. Check server logs.' })
      controller.close()
    },
  })

  return new Response(stream, {
    headers: {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      Connection: 'keep-alive',
    },
  })
})

app.get('/api/scans', (c) => {
  const userId = resolveUserId(c.req.header('x-aegis-user'))
  const data = localStore.read()
  return c.json({
    challenges: data.challenges.filter((ch) => ch.user_id === userId),
    runs: data.runs.filter((r) => r.user_id === userId),
  })
})

app.get('/api/challenges', (c) => {
  const userId = resolveUserId(c.req.header('x-aegis-user'))
  const data = localStore.read()
  return c.json({
    challenges: data.challenges.filter((ch) => ch.user_id === userId),
    runs: data.runs.filter((r) => r.user_id === userId),
  })
})

app.get('/api/history', (c) => {
  const userId = resolveUserId(c.req.header('x-aegis-user'))
  const data = localStore.read()
  const entries = data.runs
    .filter((r) => r.user_id === userId && r.finished_at && r.success)
    .map((r) => {
      const ch = data.challenges.find((c) => c.id === r.challenge_id)
      const raw = data.scan_results.find((s) => s.run_id === r.id)?.report
      const report = raw
        ? upgradeLegacyReport(raw, { targetUrl: ch?.target_url ?? undefined, targetTitle: ch?.title })
        : null
      if (!report) return null
      return {
        runId: r.id,
        challengeId: r.challenge_id,
        title: ch?.title ?? 'Scan',
        targetUrl: ch?.target_url ?? undefined,
        finishedAt: r.finished_at!,
        securityScore: report.securityScore,
        grade: report.grade,
        vulnerabilityCount: report.vulnerabilities.length,
        technologies: report.technologies,
      }
    })
    .filter(Boolean)
    .sort((a, b) => new Date(b!.finishedAt).getTime() - new Date(a!.finishedAt).getTime())

  let comparison = null
  if (entries.length >= 2) {
    const curr = data.scan_results.find((s) => s.run_id === entries[0]!.runId)?.report
    const prev = data.scan_results.find((s) => s.run_id === entries[1]!.runId)?.report
    if (curr && prev) {
      const currV = new Set(curr.vulnerabilities.map((v) => v.title))
      const prevV = new Set(prev.vulnerabilities.map((v) => v.title))
      comparison = {
        fixed: [...prevV].filter((t) => !currV.has(t)),
        introduced: [...currV].filter((t) => !prevV.has(t)),
        scoreDelta: curr.securityScore - prev.securityScore,
        previousScore: prev.securityScore,
        currentScore: curr.securityScore,
      }
    }
  }

  return c.json({ entries, comparison })
})

app.get('/api/runs/:runId/chat', (c) => {
  const runId = c.req.param('runId')
  const data = localStore.read()
  const session = data.chat_sessions.find((s) => s.run_id === runId)
  return c.json({ messages: session?.messages ?? [] })
})

app.post('/api/runs/:runId/chat', async (c) => {
  if (!hasOpenRouterKey()) {
    return c.json({ error: 'API key missing' }, 503)
  }
  const runId = c.req.param('runId')
  const body = await c.req.json<{ message: string }>()
  if (!body.message?.trim()) {
    return c.json({ error: 'Message required' }, 400)
  }

  const resolved = resolveReport(runId)
  if (!resolved?.report) {
    return c.json({ error: 'Complete a scan before chatting' }, 400)
  }

  const data = localStore.read()
  const existing = data.chat_sessions.find((s) => s.run_id === runId)
  const history = existing?.messages ?? []

  const { runScanChat } = await import('../lib/aegis/agents/chat')
  try {
    const result = await runScanChat({
      report: resolved.report,
      message: body.message.trim(),
      history: history.map((m) => ({ role: m.role, content: m.content })),
    })
    const now = new Date().toISOString()
    const userMsg = { role: 'user' as const, content: body.message.trim(), at: now }
    const assistantMsg = { role: 'assistant' as const, content: result.text, at: new Date().toISOString() }

    localStore.write((d) => {
      const idx = d.chat_sessions.findIndex((s) => s.run_id === runId)
      const next = [...history, userMsg, assistantMsg]
      if (idx >= 0) d.chat_sessions[idx] = { run_id: runId, messages: next }
      else d.chat_sessions.push({ run_id: runId, messages: next })
    })

    return c.json({ reply: result.text, messages: [...history, userMsg, assistantMsg] })
  } catch (err) {
    const e = mapToAegisError(err)
    return c.json({ error: e.userMessage }, 500)
  }
})

export default app
