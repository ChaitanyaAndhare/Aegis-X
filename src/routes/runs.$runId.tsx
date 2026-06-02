import { createFileRoute } from '@tanstack/react-router'
import { useEffect, useState } from 'react'
import { getRun, subscribeRun } from '../lib/api'
import type { IntelligenceReport } from '../lib/types'
import { AssessmentShell } from '@/components/assessment/AssessmentShell'
import { PipelineLoader } from '@/components/intelligence/PipelineLoader'
import { Alert } from '@/components/ui/alert'

export const Route = createFileRoute('/runs/$runId')({
  component: RunPage,
})

const AGENTS = ['pentest', 'evidence', 'rules', 'threat', 'risk', 'roadmap']

function RunPage() {
  const { runId } = Route.useParams()
  const [report, setReport] = useState<IntelligenceReport | null>(null)
  const [status, setStatus] = useState<'running' | 'completed' | 'failed'>('running')
  const [error, setError] = useState<string | null>(null)
  const [activeAgent, setActiveAgent] = useState(1)
  const [upgraded, setUpgraded] = useState(false)

  useEffect(() => {
    const apply = (r: Awaited<ReturnType<typeof getRun>>) => {
      if (r.report) setReport(r.report)
      setStatus(r.status)
      if (r.error) setError(r.error.message)
      setUpgraded(Boolean(r.upgradedFromLegacy))
      const last = r.steps.filter((s) => s.step < 900).at(-1)?.agent_name
      setActiveAgent(last ? Math.max(AGENTS.indexOf(last) + 1, 1) : 1)
    }

    getRun(runId).then(apply).catch(() => setError('Failed to load'))
    return subscribeRun(
      runId,
      (s) => {
        const i = AGENTS.indexOf(s.agent)
        if (i >= 0) setActiveAgent(i + 1)
      },
      (d) => {
        if (d.error?.message) {
          setError(d.error.message)
          setStatus('failed')
        }
        if (d.report) {
          setReport(d.report)
          setStatus('completed')
        } else if (!d.error) getRun(runId).then(apply)
      },
    )
  }, [runId])

  if (status === 'running' && !report) {
    return <PipelineLoader activeStep={activeAgent} />
  }

  if (status === 'failed' && !report) {
    return (
      <div className="space-y-3">
        <Alert variant="destructive">{error ?? 'Scan failed'}</Alert>
        <button type="button" className="thm-btn-outline text-xs" onClick={() => (window.location.href = '/')}>
          Try again
        </button>
      </div>
    )
  }

  if (!report) {
    return <Alert variant="destructive">{error ?? 'No report yet'}</Alert>
  }

  return (
    <>
      {upgraded && (
        <p className="mb-6 text-xs text-muted-foreground">Legacy report — run a new assessment for full analysis.</p>
      )}
      <AssessmentShell report={report} runId={runId} onRescan={() => (window.location.href = '/')} />
    </>
  )
}
