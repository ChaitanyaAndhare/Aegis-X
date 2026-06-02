import { useState } from 'react'
import type { IntelligenceReport } from '@/lib/types'
import type { EvidenceFinding } from '@/lib/platform/types'
import { displayTargetLabel, sanitizeForDisplay } from '@/lib/platform/display-sanitize'
import { downloadSecurityReport } from '@/lib/pdf-report'
import { FindingDrawer } from '@/components/platform/FindingDrawer'
import { ThreatExposureGraph } from '@/components/platform/ThreatExposureGraph'
import { ScanChatbot } from '@/components/intelligence/ScanChatbot'
import { Badge } from '@/components/ui/badge'
import { ChevronDown, FileDown, RefreshCw } from 'lucide-react'
import { cn } from '@/lib/utils'

export function AssessmentDashboard({
  report,
  runId,
  onRescan,
}: {
  report: IntelligenceReport
  runId: string
  onRescan?: () => void
}) {
  const p = report.platform!
  const [finding, setFinding] = useState<EvidenceFinding | null>(null)
  const [showGraph, setShowGraph] = useState(false)

  const label = displayTargetLabel(report.targetUrl, report.targetTitle)
  const summary = sanitizeForDisplay(p.observedPosture?.summary ?? report.executiveV2.overallPosture)
  const stack = [...p.technicalProfile.frameworks, ...p.technicalProfile.authProviders].slice(0, 6)
  const paths = p.topAttackPaths.filter((x) => x.id !== 'none').slice(0, 3)

  const sev = (s: string) =>
    (['critical', 'high', 'medium', 'low'].includes(s) ? s : 'muted') as 'critical' | 'high' | 'medium' | 'low' | 'muted'

  return (
    <div className="space-y-8 pb-16">
      <header className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="text-xl font-semibold">{label}</h1>
          {stack.length > 0 && (
            <p className="mt-2 text-xs text-muted-foreground">{stack.join(' · ')}</p>
          )}
        </div>
        <div className="flex gap-2">
          <button type="button" onClick={() => downloadSecurityReport(report)} className="thm-btn-outline text-sm">
            <FileDown className="h-4 w-4" /> Export
          </button>
          {onRescan && (
            <button type="button" onClick={onRescan} className="thm-btn text-sm">
              <RefreshCw className="h-4 w-4" /> New scan
            </button>
          )}
        </div>
      </header>

      <div className="grid grid-cols-3 gap-3 border-y border-thm-border py-6">
        <Stat label="Risk score" value={`${report.securityScore}`} detail={`Grade ${report.grade}`} />
        <Stat label="Coverage" value={`${p.evidenceCoverage.percent}%`} detail="Assessed scope" />
        <Stat label="Confidence" value={`${p.assessmentConfidence.percent}%`} detail="Evidence strength" />
      </div>

      <section>
        <p className="text-sm leading-relaxed text-muted-foreground">{summary}</p>
        <p className="mt-4 text-sm">
          <span className="text-muted-foreground">Priority: </span>
          {sanitizeForDisplay(report.executiveV2.priorityFix)}
        </p>
      </section>

      <section>
        <h2 className="text-sm font-semibold">Findings</h2>
        <table className="mt-3 w-full text-sm">
          <thead>
            <tr className="border-b border-thm-border text-left text-xs text-muted-foreground">
              <th className="pb-2 font-medium">Issue</th>
              <th className="pb-2 font-medium">Severity</th>
              <th className="pb-2 font-medium">Confidence</th>
            </tr>
          </thead>
          <tbody>
            {p.findings.map((f) => (
              <tr
                key={f.id}
                className="cursor-pointer border-b border-thm-border/40 hover:bg-white/[0.02]"
                onClick={() => setFinding(f)}
              >
                <td className="py-3 pr-4">{f.title}</td>
                <td className="py-3 pr-4">
                  <Badge variant={sev(f.severity)}>{f.severity}</Badge>
                </td>
                <td className="py-3 text-muted-foreground">{f.confidenceLevel}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>

      {p.remediationRoadmap.length > 0 && (
        <section>
          <h2 className="text-sm font-semibold">Remediation</h2>
          <ol className="mt-3 space-y-2 text-sm">
            {p.remediationRoadmap.slice(0, 5).map((r) => (
              <li key={r.priority} className="flex gap-3">
                <span className="text-primary font-medium tabular-nums">{r.priority}.</span>
                <span className="flex-1 text-muted-foreground">{sanitizeForDisplay(r.fix)}</span>
              </li>
            ))}
          </ol>
        </section>
      )}

      {paths.length > 0 && (
        <section>
          <h2 className="text-sm font-semibold">Attack paths</h2>
          <ul className="mt-3 space-y-2 text-sm text-muted-foreground">
            {paths.map((path) => (
              <li key={path.id}>
                <span className="text-foreground">{sanitizeForDisplay(path.name)}</span>
                <span className="mt-0.5 block font-mono text-xs">{path.steps.join(' → ')}</span>
              </li>
            ))}
          </ul>
        </section>
      )}

      <section>
        <button
          type="button"
          onClick={() => setShowGraph((v) => !v)}
          className="flex w-full items-center justify-between text-sm font-semibold"
        >
          Exposure graph
          <ChevronDown className={cn('h-4 w-4 transition', showGraph && 'rotate-180')} />
        </button>
        {showGraph && (
          <div className="mt-4 rounded-lg border border-thm-border p-3">
            <ThreatExposureGraph nodes={p.threatExposureGraph.nodes} edges={p.threatExposureGraph.edges} />
          </div>
        )}
      </section>

      <FindingDrawer finding={finding} onClose={() => setFinding(null)} />
      <ScanChatbot runId={runId} />
    </div>
  )
}

function Stat({ label, value, detail }: { label: string; value: string; detail: string }) {
  return (
    <div>
      <p className="text-xs text-muted-foreground">{label}</p>
      <p className="mt-1 text-2xl font-semibold tabular-nums">{value}</p>
      <p className="text-[10px] text-muted-foreground">{detail}</p>
    </div>
  )
}
