import { useState } from 'react'
import type { IntelligenceReport } from '@/lib/types'
import type { EvidenceFinding } from '@/lib/platform/types'
import { displayTargetLabel, sanitizeForDisplay } from '@/lib/platform/display-sanitize'
import { downloadSecurityReport } from '@/lib/pdf-report'
import { FindingDrawer } from '@/components/platform/FindingDrawer'
import { ThreatExposureGraph } from '@/components/platform/ThreatExposureGraph'
import { ScanChatbot } from '@/components/intelligence/ScanChatbot'
import { Badge } from '@/components/ui/badge'
import { cn } from '@/lib/utils'
import { FileDown, RefreshCw } from 'lucide-react'

const NAV = [
  { id: 'overview', label: 'Overview' },
  { id: 'findings', label: 'Findings' },
  { id: 'graph', label: 'Threat graph' },
  { id: 'assets', label: 'Assets' },
  { id: 'controls', label: 'Controls' },
  { id: 'roadmap', label: 'Roadmap' },
] as const

type Section = (typeof NAV)[number]['id']

export function AssessmentShell({
  report,
  runId,
  onRescan,
}: {
  report: IntelligenceReport
  runId: string
  onRescan?: () => void
}) {
  const p = report.platform!
  const [section, setSection] = useState<Section>('overview')
  const [finding, setFinding] = useState<EvidenceFinding | null>(null)

  const label = displayTargetLabel(report.targetUrl, report.targetTitle)
  const scanned = new Date(report.generatedAt).toLocaleString()
  const verifiedCount = p.findings.filter((f) => f.verificationStatus === 'verified').length
  const activeCount = p.findings.filter((f) => f.checkId).length

  const sev = (s: string) =>
    (['critical', 'high', 'medium', 'low'].includes(s) ? s : 'muted') as 'critical' | 'high' | 'medium' | 'low' | 'muted'

  return (
    <div className="flex min-h-[calc(100vh-4rem)] gap-0 -mx-6">
      <aside className="w-48 shrink-0 border-r border-thm-border px-3 py-2">
        <nav className="space-y-0.5">
          {NAV.map((item) => (
            <button
              key={item.id}
              type="button"
              onClick={() => setSection(item.id)}
              className={cn(
                'w-full rounded px-2 py-1.5 text-left text-xs font-medium transition',
                section === item.id
                  ? 'bg-primary/15 text-primary'
                  : 'text-muted-foreground hover:bg-white/[0.04] hover:text-foreground',
              )}
            >
              {item.label}
            </button>
          ))}
        </nav>
      </aside>

      <div className="min-w-0 flex-1 px-6 pb-16">
        <header className="flex flex-wrap items-start justify-between gap-4 border-b border-thm-border py-4">
          <div>
            <h1 className="text-lg font-semibold">{label}</h1>
            <p className="mt-1 text-xs text-muted-foreground">
              Pentest completed {scanned} · {verifiedCount} verified · {activeCount} active checks
            </p>
          </div>
          <div className="flex gap-2">
            <button type="button" onClick={() => downloadSecurityReport(report)} className="thm-btn-outline text-xs">
              <FileDown className="h-3.5 w-3.5" /> Export
            </button>
            {onRescan && (
              <button type="button" onClick={onRescan} className="thm-btn text-xs">
                <RefreshCw className="h-3.5 w-3.5" /> Rescan
              </button>
            )}
          </div>
        </header>

        {section === 'overview' && (
          <div className="space-y-8 py-6">
            <div className="grid grid-cols-2 gap-3 sm:grid-cols-5">
              <Metric label="Risk score" value={String(report.securityScore)} sub={`Grade ${report.grade}`} />
              <Metric label="Verified" value={String(verifiedCount)} sub="Active probes confirmed" />
              <Metric label="Security debt" value={String(p.securityDebt.total)} sub="Control gaps" />
              <Metric label="Coverage" value={`${p.evidenceCoverage.percent}%`} sub="Assessed scope" />
              <Metric label="Confidence" value={`${p.assessmentConfidence.percent}%`} sub="Evidence strength" />
            </div>
            {report.expertAssessment && (
              <p className="rounded border border-thm-border bg-white/[0.02] px-3 py-2 text-xs text-muted-foreground">
                {sanitizeForDisplay(report.expertAssessment.redTeamVerdict ?? '')}
              </p>
            )}
            <p className="text-sm leading-relaxed text-muted-foreground">
              {sanitizeForDisplay(p.observedPosture?.summary ?? report.executiveSummary)}
            </p>
            <div className="grid gap-6 lg:grid-cols-2">
              <Panel title="Top findings">
                <ul className="space-y-2 text-sm">
                  {p.topFindings.slice(0, 5).map((f) => (
                    <li key={f.id} className="flex items-center justify-between gap-2">
                      <button type="button" className="text-left hover:text-primary" onClick={() => setFinding(f)}>
                        {f.title}
                      </button>
                      <Badge variant={sev(f.severity)}>{f.severity}</Badge>
                    </li>
                  ))}
                </ul>
              </Panel>
              <Panel title="Top threats">
                <ul className="space-y-2 text-sm text-muted-foreground">
                  {p.topThreats.slice(0, 5).map((t) => (
                    <li key={t.id}>{t.name}</li>
                  ))}
                </ul>
              </Panel>
            </div>
            <Panel title="Threat graph (preview)">
              <div className="h-64 rounded border border-thm-border">
                <ThreatExposureGraph nodes={p.threatExposureGraph.nodes} edges={p.threatExposureGraph.edges} />
              </div>
            </Panel>
            <Panel title="Roadmap (preview)">
              <ol className="space-y-2 text-sm text-muted-foreground">
                {p.remediationRoadmap.slice(0, 4).map((r) => (
                  <li key={r.priority}>
                    <span className="text-primary">{r.priority}.</span> {sanitizeForDisplay(r.fix)}
                  </li>
                ))}
              </ol>
            </Panel>
          </div>
        )}

        {section === 'findings' && (
          <div className="py-6">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-thm-border text-left text-xs text-muted-foreground">
                  <th className="pb-2 font-medium">Severity</th>
                  <th className="pb-2 font-medium">Status</th>
                  <th className="pb-2 font-medium">Title</th>
                  <th className="pb-2 font-medium">Evidence</th>
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
                    <td className="py-3 pr-3">
                      <Badge variant={sev(f.severity)}>{f.severity}</Badge>
                    </td>
                    <td className="py-3 pr-3">
                      {f.verificationStatus ? (
                        <Badge variant={f.verificationStatus === 'verified' ? 'high' : 'medium'}>
                          {f.verificationStatus}
                        </Badge>
                      ) : (
                        <span className="text-muted-foreground">observed</span>
                      )}
                    </td>
                    <td className="py-3 pr-3">{f.title}</td>
                    <td className="max-w-xs truncate py-3 pr-3 text-muted-foreground">{f.observedSignal}</td>
                    <td className="py-3 text-muted-foreground">{f.confidenceScore}%</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {section === 'graph' && (
          <div className="py-6">
            <div className="h-[480px] rounded border border-thm-border p-2">
              <ThreatExposureGraph nodes={p.threatExposureGraph.nodes} edges={p.threatExposureGraph.edges} />
            </div>
          </div>
        )}

        {section === 'assets' && (
          <div className="space-y-6 py-6 text-sm">
            <AssetBlock title="Technologies" items={report.technologies} />
            <AssetBlock title="Attack surface" items={report.attackSurface} />
            <AssetBlock
              title="Architecture assets"
              items={p.architectureModel.assets.map((a) => `${a.type}: ${a.name}`)}
            />
            <p className="text-xs text-muted-foreground">
              Auth signals: {report.reconInsights?.authModel ?? 'Not observed'}
            </p>
          </div>
        )}

        {section === 'controls' && (
          <div className="py-6">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-thm-border text-left text-xs text-muted-foreground">
                  <th className="pb-2 font-medium">Domain</th>
                  <th className="pb-2 font-medium">Status</th>
                  <th className="pb-2 font-medium">Reasoning</th>
                </tr>
              </thead>
              <tbody>
                {p.controlCoverage.map((c) => (
                  <tr key={c.domain} className="border-b border-thm-border/40">
                    <td className="py-3 pr-4">{c.domain}</td>
                    <td className="py-3 pr-4">
                      <Badge variant={c.status === 'Good' ? 'low' : c.status === 'Poor' ? 'high' : 'medium'}>
                        {c.status}
                      </Badge>
                    </td>
                    <td className="py-3 text-muted-foreground">{c.reasoning}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {section === 'roadmap' && (
          <div className="py-6">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-thm-border text-left text-xs text-muted-foreground">
                  <th className="pb-2 font-medium">Priority</th>
                  <th className="pb-2 font-medium">Action</th>
                  <th className="pb-2 font-medium">Effort</th>
                  <th className="pb-2 font-medium">Risk reduction</th>
                </tr>
              </thead>
              <tbody>
                {p.remediationRoadmap.map((r) => (
                  <tr key={r.priority} className="border-b border-thm-border/40">
                    <td className="py-3 pr-4 tabular-nums">{r.priority}</td>
                    <td className="py-3 pr-4">{sanitizeForDisplay(r.fix)}</td>
                    <td className="py-3 pr-4 text-muted-foreground">{r.effort}</td>
                    <td className="py-3 text-muted-foreground">{r.riskReductionPercent}%</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        <FindingDrawer finding={finding} onClose={() => setFinding(null)} />
        <ScanChatbot runId={runId} />
      </div>
    </div>
  )
}

function Metric({ label, value, sub }: { label: string; value: string; sub: string }) {
  return (
    <div className="rounded border border-thm-border px-3 py-3">
      <p className="text-[10px] uppercase tracking-wide text-muted-foreground">{label}</p>
      <p className="mt-1 text-xl font-semibold tabular-nums">{value}</p>
      <p className="text-[10px] text-muted-foreground">{sub}</p>
    </div>
  )
}

function Panel({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section>
      <h2 className="text-sm font-semibold">{title}</h2>
      <div className="mt-3">{children}</div>
    </section>
  )
}

function AssetBlock({ title, items }: { title: string; items: string[] }) {
  if (!items.length) return null
  return (
    <section>
      <h2 className="text-sm font-semibold">{title}</h2>
      <ul className="mt-2 max-h-48 overflow-y-auto space-y-1 font-mono text-xs text-muted-foreground">
        {items.map((item, i) => (
          <li key={`${item}-${i}`}>{item}</li>
        ))}
      </ul>
    </section>
  )
}
