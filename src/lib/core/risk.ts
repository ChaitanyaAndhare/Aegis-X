import type { Severity } from '../types'
import { riskLevelFromScore, scoreToGrade } from '../aegis/scoring'
import type { PentestFinding } from '../pentest/types'
import type { DiscoveryResult, RuleFinding } from './types'

const SEVERITY_PENALTY: Record<Severity, number> = {
  critical: 22,
  high: 14,
  medium: 8,
  low: 3,
  info: 1,
}

export function computeRiskMetrics(
  discovery: DiscoveryResult,
  findings: RuleFinding[],
  factCount: number,
  pentestFindings: PentestFinding[] = [],
) {
  let riskScore = 88
  let securityDebt = 0

  for (const f of findings) {
    let pen = SEVERITY_PENALTY[f.severity]
    if (f.verificationStatus === 'verified') pen = Math.round(pen * 1.25)
    riskScore -= pen
    securityDebt += pen
  }

  const verifiedCount = pentestFindings.filter((p) => p.status === 'verified').length
  if (verifiedCount > 0) riskScore -= verifiedCount * 3

  if (discovery.cleartext) riskScore -= 12
  if (!discovery.hsts && !discovery.cleartext) riskScore -= 6

  riskScore = Math.max(8, Math.min(98, Math.round(riskScore)))

  const assessedAreas = [
    { id: 'headers', label: 'HTTP security headers', assessed: true },
    { id: 'tls', label: 'Transport (TLS/HSTS)', assessed: true },
    { id: 'assets', label: 'Public assets & routes', assessed: true },
    { id: 'active', label: 'Active vulnerability probes', assessed: true },
    { id: 'injection', label: 'Injection (XSS/SQLi/path)', assessed: pentestFindings.some((p) => p.category === 'injection') },
    { id: 'cookies', label: 'Cookie flags', assessed: discovery.hasCookies },
    { id: 'auth', label: 'Authentication surface', assessed: discovery.hasAuth },
    { id: 'backend', label: 'Backend authorization', assessed: false },
    { id: 'infra', label: 'Cloud infrastructure', assessed: false },
  ]

  const assessedCount = assessedAreas.filter((a) => a.assessed).length
  const coveragePercent = Math.round((assessedCount / assessedAreas.length) * 100)

  const confidenceBase = 40 + Math.min(35, factCount) + Math.min(20, findings.length * 4)
  const confidencePercent = Math.min(96, Math.max(35, confidenceBase))

  const label =
    riskScore >= 75
      ? 'Favorable observed controls'
      : riskScore >= 55
        ? 'Mixed observed posture'
        : 'Elevated observable gaps'

  const summary = [
    `${findings.length} finding(s) from pentest + rules (${verifiedCount} actively verified).`,
    `Coverage ${coveragePercent}% of defined external areas.`,
    discovery.cleartext
      ? 'Cleartext transport observed at entry.'
      : discovery.hsts
        ? 'HTTPS with HSTS observed.'
        : 'HTTPS without confirmed HSTS.',
    'Assessment is passive and external — not a penetration test.',
  ].join(' ')

  return {
    riskScore,
    grade: scoreToGrade(riskScore),
    riskLevel: riskLevelFromScore(riskScore),
    securityDebt,
    coveragePercent,
    confidencePercent,
    observedPosture: { label, summary },
    assessedAreas,
  }
}
