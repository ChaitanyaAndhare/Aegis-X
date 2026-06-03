/**
 * Enterprise ASM dashboard — Executive / Technical split view
 */

import { useState } from 'react'
import {
  Shield,
  Activity,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Lock,
  ChevronRight,
} from 'lucide-react'
import type { ScanResult, SecurityFinding, Severity } from '@/backend/core/types'

type ViewMode = 'executive' | 'technical'

export function EnterpriseDashboard({ scanResult }: { scanResult: ScanResult }) {
  const [viewMode, setViewMode] = useState<ViewMode>('executive')
  const [selectedFinding, setSelectedFinding] = useState<SecurityFinding | null>(null)
  const [navSection, setNavSection] = useState<'pages' | 'cookies' | 'headers'>('pages')

  const { securityDebt, findings, assetInventory, delta } = scanResult

  const severityClass = (severity: Severity): string => {
    const colors: Record<Severity, string> = {
      CRITICAL: 'border-red-500/40 bg-red-500/10 text-red-400',
      HIGH: 'border-orange-500/40 bg-orange-500/10 text-orange-400',
      MEDIUM: 'border-yellow-500/40 bg-yellow-500/10 text-yellow-300',
      LOW: 'border-blue-500/40 bg-blue-500/10 text-blue-300',
      INFO: 'border-thm-border bg-muted/30 text-muted-foreground',
    }
    return colors[severity]
  }

  const highlightEvidence = (raw: string, finding: SecurityFinding) => {
    const needle = raw.length > 80 ? raw.slice(0, 80) : raw
    if (finding.evidence.rawObserved && raw.includes(finding.evidence.rawObserved)) {
      const parts = raw.split(finding.evidence.rawObserved)
      return (
        <>
          {parts[0]}
          <mark className="bg-yellow-500/30 text-yellow-100">{finding.evidence.rawObserved}</mark>
          {parts[1]}
        </>
      )
    }
    return raw.slice(0, 2000) || needle
  }

  return (
    <div className="flex min-h-[calc(100vh-8rem)] flex-col gap-0 rounded-lg border border-thm-border bg-card">
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-thm-border px-4 py-3">
        <div>
          <p className="text-xs font-medium uppercase tracking-wider text-muted-foreground">ASM · Deterministic ETL</p>
          <h2 className="text-lg font-semibold">{assetInventory.targetUrl}</h2>
        </div>
        <div className="flex items-center gap-1 rounded-lg border border-thm-border bg-muted/40 p-1 text-sm">
          <button
            type="button"
            onClick={() => setViewMode('executive')}
            className={`rounded-md px-3 py-1.5 font-medium transition-colors ${
              viewMode === 'executive' ? 'bg-background text-foreground shadow-sm' : 'text-muted-foreground'
            }`}
          >
            Executive View
          </button>
          <span className="px-1 text-muted-foreground">↔</span>
          <button
            type="button"
            onClick={() => setViewMode('technical')}
            className={`rounded-md px-3 py-1.5 font-medium transition-colors ${
              viewMode === 'technical' ? 'bg-background text-foreground shadow-sm' : 'text-muted-foreground'
            }`}
          >
            Technical View
          </button>
        </div>
      </div>

      {viewMode === 'executive' ? (
        <div className="grid gap-4 p-4 lg:grid-cols-2">
          <section className="rounded-lg border border-thm-border p-4 lg:col-span-2">
            <h3 className="mb-3 flex items-center gap-2 text-sm font-semibold">
              <Shield className="h-4 w-4 text-primary" />
              Security Debt
            </h3>
            <div className="grid grid-cols-2 gap-3 sm:grid-cols-5">
              <div className="rounded-md border border-thm-border p-3 text-center">
                <div
                  className={`text-3xl font-bold tabular-nums ${
                    securityDebt.totalScore > 75 ? 'text-red-400' : securityDebt.totalScore > 50 ? 'text-orange-400' : 'text-green-400'
                  }`}
                >
                  {securityDebt.totalScore}
                </div>
                <p className="mt-1 text-xs text-muted-foreground">Debt score</p>
              </div>
              {(['criticalCount', 'highCount', 'mediumCount', 'lowCount'] as const).map((key, i) => {
                const labels = ['Critical', 'High', 'Medium', 'Low']
                const colors = ['text-red-400', 'text-orange-400', 'text-yellow-300', 'text-blue-300']
                return (
                  <div key={key} className="rounded-md border border-thm-border p-3 text-center">
                    <div className={`text-2xl font-bold tabular-nums ${colors[i]}`}>{securityDebt[key]}</div>
                    <p className="mt-1 text-xs text-muted-foreground">{labels[i]}</p>
                  </div>
                )
              })}
            </div>
            <p className="mt-3 flex items-center gap-2 text-xs text-muted-foreground">
              {securityDebt.trend === 'improving' && <CheckCircle className="h-4 w-4 text-green-500" />}
              {securityDebt.trend === 'degrading' && <XCircle className="h-4 w-4 text-red-500" />}
              {securityDebt.trend === 'stable' && <Activity className="h-4 w-4" />}
              Trend: {securityDebt.trend}
              {delta && (
                <span className="ml-2">
                  · +{delta.newFindings.length} new / −{delta.resolvedFindings.length} resolved
                </span>
              )}
            </p>
          </section>

          <section className="rounded-lg border border-thm-border p-4">
            <h3 className="mb-3 flex items-center gap-2 text-sm font-semibold">
              <AlertTriangle className="h-4 w-4" />
              Compliance (rule-derived)
            </h3>
            <ul className="space-y-2 text-sm">
              {(
                [
                  ['PCI-DSS', securityDebt.complianceFlags.pciDss],
                  ['SOC 2', securityDebt.complianceFlags.soc2],
                  ['GDPR', securityDebt.complianceFlags.gdpr],
                  ['HIPAA', securityDebt.complianceFlags.hipaa],
                ] as const
              ).map(([label, ok]) => (
                <li key={label} className="flex justify-between">
                  <span className="text-muted-foreground">{label}</span>
                  {ok ? <CheckCircle className="h-4 w-4 text-green-500" /> : <XCircle className="h-4 w-4 text-red-500" />}
                </li>
              ))}
            </ul>
          </section>

          <section className="rounded-lg border border-thm-border p-4">
            <h3 className="mb-2 text-sm font-semibold">Attack surface summary</h3>
            <ul className="space-y-1 text-xs text-muted-foreground">
              <li>Org profile: {assetInventory.orgType}</li>
              <li>Endpoints observed: {assetInventory.endpoints.length}</li>
              <li>Open ports: {assetInventory.openPorts?.join(', ') || '—'}</li>
              <li>Scan duration: {scanResult.duration}s</li>
            </ul>
          </section>

          <section className="rounded-lg border border-thm-border p-4 lg:col-span-2">
            <h3 className="mb-3 text-sm font-semibold">Priority actions</h3>
            <div className="space-y-2">
              {findings.slice(0, 6).map((f) => (
                <button
                  key={f.id}
                  type="button"
                  onClick={() => {
                    setSelectedFinding(f)
                    setViewMode('technical')
                  }}
                  className={`flex w-full items-center justify-between rounded-md border px-3 py-2 text-left text-sm ${severityClass(f.contextualSeverity)}`}
                >
                  <span>{f.title}</span>
                  <ChevronRight className="h-4 w-4 shrink-0 opacity-60" />
                </button>
              ))}
            </div>
          </section>
        </div>
      ) : (
        <div className="grid flex-1 gap-0 lg:grid-cols-[240px_1fr]">
          <aside className="border-b border-thm-border p-3 lg:border-b-0 lg:border-r">
            <p className="mb-2 text-xs font-medium uppercase text-muted-foreground">Asset navigator</p>
            <nav className="space-y-1 text-sm">
              {(['pages', 'cookies', 'headers'] as const).map((id) => (
                <button
                  key={id}
                  type="button"
                  onClick={() => setNavSection(id)}
                  className={`block w-full rounded px-2 py-1.5 text-left capitalize ${
                    navSection === id ? 'bg-primary/15 text-primary' : 'text-muted-foreground hover:bg-muted/50'
                  }`}
                >
                  {id === 'pages' ? 'Discovered pages' : id}
                </button>
              ))}
            </nav>
            <div className="mt-4 max-h-64 overflow-y-auto text-xs">
              {navSection === 'pages' &&
                assetInventory.endpoints
                  .filter((e) => e.type === 'static' || e.type === 'api')
                  .slice(0, 15)
                  .map((e, i) => (
                    <div key={i} className="truncate py-1 font-mono text-muted-foreground">
                      {e.method} {e.url}
                    </div>
                  ))}
              {navSection === 'cookies' &&
                assetInventory.cookies.map((c, i) => (
                  <div key={i} className="border-b border-thm-border/50 py-2">
                    <div className="font-medium">{c.name}</div>
                    <div className="text-muted-foreground">
                      {c.secure ? 'Secure ' : ''}
                      {c.httpOnly ? 'HttpOnly ' : ''}
                      {c.sameSite ?? 'no SameSite'}
                    </div>
                  </div>
                ))}
              {navSection === 'headers' &&
                Object.entries(assetInventory.headers).map(([k, v]) => (
                  <div key={k} className="py-1 font-mono">
                    <span className="text-primary">{k}:</span> {v}
                  </div>
                ))}
            </div>
          </aside>

          <div className="flex flex-col gap-4 p-4">
            <div className="grid gap-4 lg:grid-cols-2">
              <div className="max-h-[420px] overflow-y-auto rounded-lg border border-thm-border">
                <div className="border-b border-thm-border px-3 py-2 text-sm font-semibold">Findings</div>
                {findings.map((f) => (
                  <button
                    key={f.id}
                    type="button"
                    onClick={() => setSelectedFinding(f)}
                    className={`block w-full border-b border-thm-border/50 px-3 py-2 text-left text-sm last:border-0 ${
                      selectedFinding?.id === f.id ? 'bg-muted/50' : ''
                    }`}
                  >
                    <span className={`inline-block rounded px-1.5 py-0.5 text-xs ${severityClass(f.contextualSeverity)}`}>
                      {f.contextualSeverity}
                    </span>
                    <span className="ml-2">{f.title}</span>
                  </button>
                ))}
              </div>

              <div className="rounded-lg border border-thm-border p-3">
                <h3 className="mb-2 flex items-center gap-2 text-sm font-semibold">
                  <Lock className="h-4 w-4" />
                  Evidence inspector
                </h3>
                {selectedFinding ? (
                  <div className="space-y-3 text-sm">
                    <p className="font-medium">{selectedFinding.title}</p>
                    <p className="text-xs text-muted-foreground">{selectedFinding.evidence.location}</p>
                    <pre className="max-h-32 overflow-auto rounded bg-zinc-950 p-2 font-mono text-xs text-green-400">
                      {selectedFinding.evidence.rawObserved}
                    </pre>
                    {selectedFinding.evidence.reproduciblePayload && (
                      <pre className="overflow-auto rounded border border-thm-border bg-muted/30 p-2 font-mono text-xs">
                        {selectedFinding.evidence.reproduciblePayload}
                      </pre>
                    )}
                    <ol className="list-decimal space-y-1 pl-4 text-xs text-muted-foreground">
                      {selectedFinding.remediationSteps.map((s, i) => (
                        <li key={i}>{s}</li>
                      ))}
                    </ol>
                    {assetInventory.httpExchanges?.[0] && (
                      <div>
                        <p className="mb-1 text-xs font-medium">Captured exchange (snippet)</p>
                        <pre className="max-h-40 overflow-auto rounded bg-zinc-950 p-2 font-mono text-[10px] text-zinc-300">
                          {highlightEvidence(
                            Object.entries(
                              assetInventory.httpExchanges.find((x) =>
                                selectedFinding.evidence.location.toLowerCase().includes('header'),
                              )?.responseHeaders ?? assetInventory.httpExchanges[0].responseHeaders,
                            )
                              .map(([k, v]) => `${k}: ${v}`)
                              .join('\n'),
                            selectedFinding,
                          )}
                        </pre>
                      </div>
                    )}
                  </div>
                ) : (
                  <p className="text-sm text-muted-foreground">Select a finding to inspect verbatim evidence.</p>
                )}
              </div>
            </div>

            <ScopeCoverage />
          </div>
        </div>
      )}

      {viewMode === 'executive' && <div className="border-t border-thm-border p-4"><ScopeCoverage /></div>}
    </div>
  )
}

function ScopeCoverage() {
  return (
    <div className="rounded-lg border border-thm-border bg-muted/20 p-3 text-sm">
      <h4 className="mb-2 font-semibold">Scope coverage</h4>
      <div className="grid gap-4 sm:grid-cols-2">
        <ul className="space-y-1 text-xs text-muted-foreground">
          <li className="font-medium text-foreground">In scope</li>
          <li>HTTP security headers</li>
          <li>Cookie attribute analysis</li>
          <li>TLS / HTTPS surface</li>
          <li>Passive DNS (A, AAAA, MX, TXT, CNAME)</li>
          <li>TCP ports 80, 443, 8080, 8443</li>
          <li>Technology fingerprinting</li>
          <li>Mixed content detection</li>
        </ul>
        <ul className="space-y-1 text-xs text-muted-foreground">
          <li className="font-medium text-foreground">Out of scope</li>
          <li>Active exploitation</li>
          <li>Business logic testing</li>
          <li>Authentication bypass</li>
          <li>Authorization / IDOR deep testing</li>
          <li>Destructive or DoS testing</li>
        </ul>
      </div>
    </div>
  )
}
