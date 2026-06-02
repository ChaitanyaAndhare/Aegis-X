import { textCall } from '../ai'
import { CHAT_PERSONA } from '../expert-prompts'
import type { IntelligenceReport } from '../../types'

function reportContext(report: IntelligenceReport): string {
  const p = report.platform
  return `Target: ${report.targetTitle ?? 'Unknown'} ${report.targetUrl ?? ''}
Observed posture: ${p?.observedPosture?.summary ?? report.executiveV2.overallPosture}
Evidence coverage: ${p?.evidenceCoverage?.percent ?? '—'}%
Assessment confidence: ${p?.assessmentConfidence?.percent ?? '—'}% — ${p?.assessmentConfidence?.reason ?? ''}
Risk score (coverage-adjusted): ${p?.riskScore ?? report.securityScore} (Grade ${report.grade})
Attackability: ${p?.attackabilityIndex ?? '—'}
Never claim the site is "secure". Transport enforcement gap: ${p?.scanSignals?.usesHttpOnly ? 'yes (observed)' : 'not flagged'}

Top findings:
${(p?.topFindings ?? report.vulnerabilities).map((v) => `- [${'severity' in v ? v.severity : '—'}] ${v.title}`).join('\n') || 'None'}

Priority fix: ${report.executiveV2.priorityFix}
Remediation:
${(p?.remediationRoadmap ?? []).map((r) => `${r.priority}. ${r.fix} (−${r.riskReductionPercent}%)`).join('\n')}

Technologies: ${report.technologies.join(', ') || 'unknown'}`
}

export async function runScanChat(input: {
  report: IntelligenceReport
  message: string
  history: { role: 'user' | 'assistant'; content: string }[]
}) {
  const system = `${CHAT_PERSONA}\n\n--- SCAN REPORT ---\n${reportContext(input.report)}`

  const messages = [
    ...input.history.slice(-10),
    { role: 'user' as const, content: input.message },
  ]

  return textCall(system, messages)
}
