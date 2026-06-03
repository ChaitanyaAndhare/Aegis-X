import { createFileRoute, Link } from '@tanstack/react-router'
import { useEffect, useState } from 'react'
import { getRun, subscribeRun } from '../lib/api'
import type { IntelligenceReport } from '../lib/types'
import { EnterpriseDashboard } from '@/components/enterprise/EnterpriseDashboard'
import { PipelineLoader } from '@/components/intelligence/PipelineLoader'
import { Alert } from '@/components/ui/alert'

export const Route = createFileRoute('/runs/$runId')({
  component: RunPage,
})

const ETL_AGENTS = ['extract', 'transform', 'risk', 'load', 'delta']

function RunPage() {
  const { runId } = Route.useParams()
  const [report, setReport] = useState<IntelligenceReport | null>(null)
  const [status, setStatus] = useState<'running' | 'completed' | 'failed'>('running')
  const [error, setError] = useState<string | null>(null)
  const [activeAgent, setActiveAgent] = useState(1)

  useEffect(() => {
    const apply = (r: Awaited<ReturnType<typeof getRun>>) => {
      if (r.report) setReport(r.report)
      setStatus(r.status)
      if (r.error) setError(r.error.message)
      const last = r.steps.filter((s) => s.step < 900).at(-1)?.agent_name
      const idx = last ? ETL_AGENTS.indexOf(last) : -1
      if (idx >= 0) setActiveAgent(idx + 1)
    }

    getRun(runId).then(apply).catch(() => setError('Failed to load'))
    return subscribeRun(
      runId,
      (s) => {
        const i = ETL_AGENTS.indexOf(s.agent)
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
      <div className="ax-container py-20">
        <Alert variant="destructive">{error ?? 'Scan failed'}</Alert>
        <Link to="/" className="ax-btn-ghost mt-6 inline-flex">
          Back
        </Link>
      </div>
    )
  }

  if (!report?.enterprise?.scanResult) {
    return (
      <div className="ax-container py-20">
        <Alert variant="destructive">{error ?? 'No report'}</Alert>
      </div>
    )
  }

  return <EnterpriseDashboard scanResult={report.enterprise.scanResult} />
}
