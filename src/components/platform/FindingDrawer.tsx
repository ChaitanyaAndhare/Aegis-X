import type { EvidenceFinding } from '@/lib/platform/types'
import { sanitizeForDisplay } from '@/lib/platform/display-sanitize'
import { X } from 'lucide-react'
import { cn } from '@/lib/utils'
import { Badge } from '@/components/ui/badge'

export function FindingDrawer({ finding, onClose }: { finding: EvidenceFinding | null; onClose: () => void }) {
  if (!finding) return null

  const status = finding.verificationStatus

  return (
    <div className="fixed inset-y-0 right-0 z-40 w-full max-w-md border-l border-thm-border bg-card shadow-xl">
      <div className="flex items-center justify-between border-b border-thm-border px-4 py-3">
        <h3 className="text-sm font-semibold pr-4">{finding.title}</h3>
        <button type="button" onClick={onClose}>
          <X className="h-4 w-4 text-muted-foreground" />
        </button>
      </div>
      <div className="space-y-4 overflow-y-auto p-4 text-sm">
        <div className="flex flex-wrap gap-2">
          <Badge
            variant={
              (['critical', 'high', 'medium', 'low'].includes(finding.severity)
                ? finding.severity
                : 'muted') as 'critical' | 'high' | 'medium' | 'low'
            }
          >
            {finding.severity}
          </Badge>
          <span className="text-xs text-muted-foreground">{finding.confidenceLevel} confidence</span>
          {status && (
            <Badge variant={status === 'verified' ? 'high' : status === 'potential' ? 'medium' : 'muted'}>
              {status}
            </Badge>
          )}
          {finding.checkId && (
            <span className="text-xs font-mono text-muted-foreground">{finding.checkId}</span>
          )}
        </div>
        <Block title="Observed" text={finding.observedSignal} />
        <Block title="Evidence" text={finding.evidence} />
        {finding.testPayload && (
          <div>
            <p className="text-xs font-medium text-muted-foreground">Educational probe</p>
            <pre className="mt-1 overflow-x-auto rounded border border-thm-border bg-black/30 p-2 font-mono text-xs">
              {sanitizeForDisplay(finding.testPayload)}
            </pre>
          </div>
        )}
        {finding.reproductionSteps && finding.reproductionSteps.length > 0 && (
          <div>
            <p className="text-xs font-medium text-muted-foreground">Reproduction</p>
            <ol className="mt-1 list-decimal space-y-1 pl-4 text-xs text-muted-foreground">
              {finding.reproductionSteps.map((step, i) => (
                <li key={i} className="font-mono break-all">
                  {sanitizeForDisplay(step)}
                </li>
              ))}
            </ol>
          </div>
        )}
        <Block title="Impact" text={finding.potentialImpact} />
        <Block title="Remediation" text={finding.recommendedFix} highlight />
      </div>
    </div>
  )
}

function Block({ title, text, highlight }: { title: string; text: string; highlight?: boolean }) {
  return (
    <div>
      <p className="text-xs font-medium text-muted-foreground">{title}</p>
      <p className={cn('mt-1 leading-relaxed', highlight && 'text-primary')}>{sanitizeForDisplay(text)}</p>
    </div>
  )
}
