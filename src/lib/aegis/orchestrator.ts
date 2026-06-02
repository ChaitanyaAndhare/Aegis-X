import { PIPELINE_STEPS, runDeterministicAssessment } from '../core/pipeline'
import { coreToIntelligenceReport } from '../core/to-report'
import { mapToAegisError, AegisError } from './errors'
import { logAegis, logError } from './log'
import { formatScanDescription, parseStackHints } from './parse-hints'
import { localStore, uuid } from '../store'

function recordStep(
  runId: string,
  step: number,
  agent: string,
  input: Record<string, unknown>,
  output: Record<string, unknown>,
  durationMs: number,
) {
  localStore.write((d) => {
    d.agent_steps.push({
      id: uuid(),
      run_id: runId,
      step,
      agent_name: agent,
      input_json: input,
      output_json: output,
      tokens: 0,
      duration_ms: durationMs,
    })
    const run = d.runs.find((r) => r.id === runId)
    if (run) run.total_steps = step
  })
}

function failRun(runId: string, err: AegisError) {
  localStore.write((d) => {
    const run = d.runs.find((r) => r.id === runId)
    if (run) {
      run.finished_at = new Date().toISOString()
      run.success = false
      run.error_code = err.code
      run.error_message = err.userMessage
    }
    const ch = d.challenges.find((c) => c.id === run?.challenge_id)
    if (ch) ch.status = 'failed'
    d.agent_steps.push({
      id: uuid(),
      run_id: runId,
      step: 999,
      agent_name: 'system',
      input_json: {},
      output_json: { code: err.code, message: err.userMessage },
      reasoning: err.userMessage,
      tokens: 0,
      duration_ms: 0,
    })
  })
}

export async function executeRun(runId: string, _userId: string) {
  const data = localStore.read()
  const run = data.runs.find((r) => r.id === runId)
  if (!run) throw new Error('Run not found')
  const challenge = data.challenges.find((c) => c.id === run.challenge_id)
  if (!challenge) throw new Error('Challenge not found')

  if (!challenge.target_url?.trim()) {
    const err = new AegisError('INVALID_URL', 'A target URL is required for deterministic assessment.')
    failRun(runId, err)
    throw err
  }

  const authorized = /\[authorized:\s*true\]/i.test(challenge.description)
  if (!authorized) {
    const err = new AegisError(
      'UNAUTHORIZED',
      'Confirm authorization to pentest this target before running (checkbox on start page).',
    )
    failRun(runId, err)
    throw err
  }

  logAegis('Pentest run started')
  const runStarted = Date.now()

  localStore.write((d) => {
    const c = d.challenges.find((x) => x.id === challenge.id)
    if (c) c.status = 'running'
  })

  try {
    const targetUrl = challenge.target_url.trim()
    const core = await runDeterministicAssessment({
      scanId: challenge.id,
      targetUrl,
      targetTitle: challenge.title,
    })

    const phaseMs = Math.max(1, Math.round(core.durationMs / PIPELINE_STEPS.length))
    for (let i = 0; i < PIPELINE_STEPS.length; i++) {
      const phase = PIPELINE_STEPS[i]
      recordStep(
        runId,
        i + 1,
        phase,
        { targetUrl },
        {
          pentestChecks: phase === 'pentest' ? core.pentest.checksRun.length : undefined,
          verified: phase === 'pentest' ? core.pentest.findings.filter((f) => f.status === 'verified').length : undefined,
          findings: phase === 'rules' ? core.findings.length : undefined,
          facts: phase === 'evidence' ? core.facts.length : undefined,
          nodes: phase === 'threat' ? core.graph.nodes.length : undefined,
          riskScore: phase === 'risk' ? core.riskScore : undefined,
          items: phase === 'roadmap' ? core.remediation.length : undefined,
        },
        phaseMs,
      )
    }

    const report = coreToIntelligenceReport(core)

    localStore.write((d) => {
      d.scan_results = d.scan_results.filter((s) => s.run_id !== runId)
      d.scan_results.push({ run_id: runId, report })
      const r = d.runs.find((x) => x.id === runId)
      if (r) {
        r.finished_at = new Date().toISOString()
        r.success = true
        r.cost_tokens = 0
        r.total_steps = PIPELINE_STEPS.length
        r.error_code = null
        r.error_message = null
      }
      const c = d.challenges.find((x) => x.id === challenge.id)
      if (c) c.status = 'completed'
      d.episodic_memory.push({
        id: uuid(),
        user_id: run.user_id,
        run_id: runId,
        summary: core.observedPosture.summary.slice(0, 500),
        outcome: core.riskScore >= 85 ? 'low_risk' : 'needs_remediation',
      })
    })

    logAegis(`Run finished in ${Date.now() - runStarted}ms`)
    return { runId, report, totalTokens: 0 }
  } catch (err) {
    const aegisErr = err instanceof AegisError ? err : mapToAegisError(err)
    failRun(runId, aegisErr)
    logError(aegisErr)
    throw aegisErr
  }
}

export function startRun(challengeId: string, userId: string) {
  const runId = uuid()
  localStore.write((d) => {
    d.runs.push({
      id: runId,
      challenge_id: challengeId,
      user_id: userId,
      started_at: new Date().toISOString(),
      total_steps: 0,
      cost_tokens: 0,
    })
  })
  return runId
}

export function createScan(opts: {
  userId: string
  title: string
  targetUrl?: string
  appDescription?: string
  apiSpec?: string
  ctfDescription?: string
  authorized?: boolean
}) {
  const description =
    [
      opts.appDescription,
      opts.ctfDescription,
      opts.authorized ? '[authorized: true]' : '',
    ]
      .filter(Boolean)
      .join('\n\n') || formatScanDescription(undefined, [])
  const id = uuid()
  localStore.write((d) => {
    d.challenges.push({
      id,
      user_id: opts.userId,
      title: opts.title || 'Security Scan',
      description,
      target_url: opts.targetUrl ?? null,
      api_spec: opts.apiSpec ?? null,
      status: 'pending',
      created_at: new Date().toISOString(),
    })
  })
  return id
}

export function createChallenge(opts: {
  userId: string
  title: string
  description: string
  targetUrl?: string
}) {
  return createScan({
    userId: opts.userId,
    title: opts.title,
    targetUrl: opts.targetUrl,
    appDescription: opts.description,
  })
}
