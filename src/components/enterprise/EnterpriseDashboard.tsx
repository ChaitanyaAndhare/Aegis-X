import { useMemo, useState } from 'react'
import { Link } from '@tanstack/react-router'
import { ArrowLeft, Check, X } from 'lucide-react'
import type { ScanResult, SecurityFinding, Severity } from '@/backend/core/types'
import { DebtRingChart } from '@/components/charts/DebtRingChart'
import { SeverityBarChart } from '@/components/charts/SeverityBarChart'
import { TrendSparkline } from '@/components/charts/TrendSparkline'
import { cn } from '@/lib/utils'

type ViewMode = 'executive' | 'technical'
type Page = 'overview' | 'findings' | 'assets' | 'evidence' | 'scope'

const PAGES: { id: Page; label: string }[] = [
  { id: 'overview', label: 'Overview' },
  { id: 'findings', label: 'Findings' },
  { id: 'assets', label: 'Assets' },
  { id: 'evidence', label: 'Evidence' },
  { id: 'scope', label: 'Scope' },
]

function severityCounts(findings: SecurityFinding[]): Record<Severity, number> {
  const c: Record<Severity, number> = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 }
  for (const f of findings) c[f.contextualSeverity]++
  return c
}

function SeverityPill({ severity }: { severity: Severity }) {
  const styles: Record<Severity, string> = {
    CRITICAL: 'bg-red-100 text-red-800',
    HIGH: 'bg-orange-100 text-orange-800',
    MEDIUM: 'bg-amber-100 text-amber-900',
    LOW: 'bg-blue-100 text-blue-800',
    INFO: 'bg-neutral-100 text-neutral-600',
  }
  return (
    <span className={cn('rounded px-2 py-0.5 text-[10px] font-medium uppercase tracking-wide', styles[severity])}>
      {severity}
    </span>
  )
}

export function EnterpriseDashboard({ scanResult }: { scanResult: ScanResult }) {
  const [viewMode, setViewMode] = useState<ViewMode>('executive')
  const [page, setPage] = useState<Page>('overview')
  const [selected, setSelected] = useState<SecurityFinding | null>(null)

  const { securityDebt, findings, assetInventory, delta } = scanResult
  const counts = useMemo(() => severityCounts(findings), [findings])
  const host = useMemo(() => {
    try {
      return new URL(assetInventory.targetUrl).hostname
    } catch {
      return assetInventory.targetUrl
    }
  }, [assetInventory.targetUrl])

  return (
    <div className="flex min-h-[calc(100vh-4rem)] flex-col bg-background">
      <header className="border-b border-border bg-card">
        <div className="flex flex-wrap items-end justify-between gap-6 px-6 py-8 md:px-10">
          <div className="min-w-0 flex-1 animate-slide-up">
            <Link to="/" className="ax-btn-ghost mb-4 -ml-2 gap-1 text-muted-foreground">
              <ArrowLeft className="h-4 w-4" />
              Back
            </Link>
            <p className="ax-label">{assetInventory.orgType}</p>
            <h1 className="mt-2 truncate font-display text-3xl md:text-4xl">{host}</h1>
          </div>

          <div className="flex rounded-md border border-border p-0.5 text-sm">
            {(['executive', 'technical'] as const).map((mode) => (
              <button
                key={mode}
                type="button"
                onClick={() => setViewMode(mode)}
                className={cn(
                  'rounded px-4 py-2 capitalize transition',
                  viewMode === mode ? 'bg-foreground text-background' : 'text-muted-foreground hover:text-foreground',
                )}
              >
                {mode}
              </button>
            ))}
          </div>
        </div>

        <nav className="flex gap-1 overflow-x-auto border-t border-border px-6 md:px-10">
          {PAGES.map((item) => (
            <button
              key={item.id}
              type="button"
              onClick={() => setPage(item.id)}
              className={cn(
                'shrink-0 border-b-2 px-4 py-3 text-sm transition',
                page === item.id
                  ? 'border-foreground text-foreground'
                  : 'border-transparent text-muted-foreground hover:text-foreground',
              )}
            >
              {item.label}
            </button>
          ))}
        </nav>
      </header>

      <div className="flex-1 px-6 py-8 md:px-10">
        {page === 'overview' && (
          <div className="mx-auto max-w-6xl space-y-8 animate-slide-up">
            <div className="grid gap-6 lg:grid-cols-[auto_1fr]">
              <div className="ax-panel flex flex-col items-center justify-center p-8">
                <DebtRingChart score={securityDebt.totalScore} size={160} />
              </div>
              <div className="ax-panel p-6">
                <p className="ax-label mb-4">Severity distribution</p>
                <SeverityBarChart counts={counts} className="mx-auto max-w-sm" />
              </div>
            </div>

            {viewMode === 'executive' && delta && (
              <div className="grid gap-6 md:grid-cols-3">
                <Stat label="New" value={delta.newFindings.length} />
                <Stat label="Resolved" value={delta.resolvedFindings.length} />
                <Stat label="Stable" value={delta.stableFindings.length} />
              </div>
            )}

            {delta && viewMode === 'executive' && (
              <div className="ax-panel p-6">
                <p className="ax-label mb-2">Delta trend</p>
                <TrendSparkline newCount={delta.newFindings.length} resolvedCount={delta.resolvedFindings.length} />
              </div>
            )}

            {viewMode === 'executive' && (
              <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
                <ComplianceRow label="PCI" ok={securityDebt.complianceFlags.pciDss} />
                <ComplianceRow label="SOC 2" ok={securityDebt.complianceFlags.soc2} />
                <ComplianceRow label="GDPR" ok={securityDebt.complianceFlags.gdpr} />
                <ComplianceRow label="HIPAA" ok={securityDebt.complianceFlags.hipaa} />
              </div>
            )}

            {viewMode === 'executive' && findings.length > 0 && (
              <section>
                <p className="ax-label mb-4">Priority</p>
                <ul className="divide-y divide-border rounded-lg border border-border bg-card">
                  {findings.slice(0, 5).map((f) => (
                    <li key={f.id}>
                      <button
                        type="button"
                        onClick={() => {
                          setSelected(f)
                          setPage('evidence')
                        }}
                        className="flex w-full items-center justify-between gap-4 px-5 py-4 text-left transition hover:bg-muted/50"
                      >
                        <span className="text-sm font-medium">{f.title}</span>
                        <SeverityPill severity={f.contextualSeverity} />
                      </button>
                    </li>
                  ))}
                </ul>
              </section>
            )}
          </div>
        )}

        {page === 'findings' && (
          <div className="mx-auto max-w-4xl animate-slide-up">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border text-left ax-label">
                  <th className="pb-3 pr-4 font-medium">Severity</th>
                  <th className="pb-3 font-medium">Finding</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {findings.map((f) => (
                  <tr
                    key={f.id}
                    className="cursor-pointer transition hover:bg-muted/40"
                    onClick={() => {
                      setSelected(f)
                      setPage('evidence')
                    }}
                  >
                    <td className="py-4 pr-4 align-top">
                      <SeverityPill severity={f.contextualSeverity} />
                    </td>
                    <td className="py-4">
                      <p className="font-medium">{f.title}</p>
                      <p className="mt-1 line-clamp-1 text-xs text-muted-foreground">{f.evidence.location}</p>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {findings.length === 0 && <Empty label="No findings" />}
          </div>
        )}

        {page === 'assets' && (
          <div className="mx-auto grid max-w-5xl gap-6 lg:grid-cols-2 animate-slide-up">
            <AssetPanel title="Technologies">
              {assetInventory.technologies.map((t, i) => (
                <div key={i} className="flex justify-between border-b border-border py-3 text-sm last:border-0">
                  <span>{t.name}</span>
                  <span className="text-muted-foreground">{t.category}</span>
                </div>
              ))}
              {!assetInventory.technologies.length && <Empty label="None detected" />}
            </AssetPanel>
            <AssetPanel title="Endpoints">
              <div className="max-h-80 space-y-2 overflow-y-auto font-mono text-xs text-muted-foreground">
                {assetInventory.endpoints.slice(0, 40).map((e, i) => (
                  <div key={i} className="truncate">
                    <span className="text-foreground">{e.method}</span> {e.url}
                  </div>
                ))}
              </div>
            </AssetPanel>
            <AssetPanel title="Cookies">
              {assetInventory.cookies.map((c, i) => (
                <div key={i} className="border-b border-border py-3 text-sm last:border-0">
                  <p className="font-medium">{c.name}</p>
                  <p className="mt-1 text-xs text-muted-foreground">
                    {[c.secure && 'Secure', c.httpOnly && 'HttpOnly', c.sameSite].filter(Boolean).join(' · ') ||
                      'No flags'}
                  </p>
                </div>
              ))}
              {!assetInventory.cookies.length && <Empty label="None" />}
            </AssetPanel>
            <AssetPanel title="DNS">
              {Object.entries(assetInventory.dnsRecords ?? {}).map(([k, vals]) =>
                (vals as string[] | undefined)?.length ? (
                  <div key={k} className="border-b border-border py-3 text-sm last:border-0">
                    <p className="ax-label">{k}</p>
                    <p className="mt-1 font-mono text-xs text-muted-foreground">{(vals as string[]).join(', ')}</p>
                  </div>
                ) : null,
              )}
            </AssetPanel>
          </div>
        )}

        {page === 'evidence' && (
          <div className="mx-auto grid max-w-6xl gap-8 lg:grid-cols-2 animate-slide-up">
            <div className="max-h-[calc(100vh-16rem)] overflow-y-auto rounded-lg border border-border">
              {findings.map((f) => (
                <button
                  key={f.id}
                  type="button"
                  onClick={() => setSelected(f)}
                  className={cn(
                    'block w-full border-b border-border px-5 py-4 text-left text-sm transition last:border-0',
                    selected?.id === f.id ? 'bg-muted' : 'hover:bg-muted/50',
                  )}
                >
                  <SeverityPill severity={f.contextualSeverity} />
                  <p className="mt-2 font-medium">{f.title}</p>
                </button>
              ))}
            </div>
            <div className="ax-panel min-h-[320px] p-6">
              {selected ? (
                <EvidencePanel finding={selected} />
              ) : (
                <p className="text-sm text-muted-foreground">Select a finding</p>
              )}
            </div>
          </div>
        )}

        {page === 'scope' && (
          <div className="mx-auto grid max-w-3xl gap-8 md:grid-cols-2 animate-slide-up">
            <ScopeList title="In scope" items={SCOPE_IN} />
            <ScopeList title="Out of scope" items={SCOPE_OUT} muted />
          </div>
        )}
      </div>
    </div>
  )
}

const SCOPE_IN = [
  'HTTP security headers',
  'Cookie attributes',
  'TLS / HTTPS',
  'Passive DNS',
  'Port reachability',
  'Technology fingerprinting',
]

const SCOPE_OUT = [
  'Active exploitation',
  'Business logic',
  'Auth bypass',
  'Destructive testing',
]

function Stat({ label, value }: { label: string; value: number }) {
  return (
    <div className="ax-panel px-6 py-5">
      <p className="ax-label">{label}</p>
      <p className="mt-2 font-display text-4xl tabular-nums">{value}</p>
    </div>
  )
}

function ComplianceRow({ label, ok }: { label: string; ok: boolean }) {
  return (
    <div className="ax-panel flex items-center justify-between px-5 py-4">
      <span className="text-sm">{label}</span>
      {ok ? <Check className="h-4 w-4 text-success" /> : <X className="h-4 w-4 text-destructive" />}
    </div>
  )
}

function AssetPanel({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="ax-panel p-6">
      <p className="ax-label mb-4">{title}</p>
      {children}
    </div>
  )
}

function EvidencePanel({ finding }: { finding: SecurityFinding }) {
  return (
    <div className="space-y-6">
      <div>
        <SeverityPill severity={finding.contextualSeverity} />
        <h2 className="mt-3 font-display text-2xl">{finding.title}</h2>
      </div>
      <div>
        <p className="ax-label">Location</p>
        <p className="mt-1 text-sm text-muted-foreground">{finding.evidence.location}</p>
      </div>
      <div>
        <p className="ax-label">Observed</p>
        <pre className="mt-2 max-h-48 overflow-auto rounded-md bg-foreground p-4 font-mono text-xs text-background">
          {finding.evidence.rawObserved}
        </pre>
      </div>
      {finding.evidence.reproduciblePayload && (
        <div>
          <p className="ax-label">Verify</p>
          <pre className="mt-2 overflow-auto rounded-md border border-border bg-muted/30 p-3 font-mono text-xs">
            {finding.evidence.reproduciblePayload}
          </pre>
        </div>
      )}
      <ol className="list-decimal space-y-2 pl-4 text-sm text-muted-foreground">
        {finding.remediationSteps.map((s, i) => (
          <li key={i}>{s}</li>
        ))}
      </ol>
    </div>
  )
}

function ScopeList({ title, items, muted }: { title: string; items: string[]; muted?: boolean }) {
  return (
    <div className="ax-panel p-6">
      <p className="ax-label mb-4">{title}</p>
      <ul className={cn('space-y-3 text-sm', muted && 'text-muted-foreground')}>
        {items.map((item) => (
          <li key={item}>{item}</li>
        ))}
      </ul>
    </div>
  )
}

function Empty({ label }: { label: string }) {
  return <p className="py-6 text-sm text-muted-foreground">{label}</p>
}
