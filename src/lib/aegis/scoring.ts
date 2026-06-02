import type { ReconOutput, ScoreBreakdownItem, Severity, SimulatedAttackPath, Vulnerability } from '../types'
import type { ScanSignals } from '../platform/evidence-engine'

/** Weights must sum to 1 */
export const SCORE_WEIGHTS = {
  posture: 0.28,
  findings: 0.42,
  attackPaths: 0.2,
  exposure: 0.1,
} as const

const SEVERITY_PENALTY: Record<Severity, number> = {
  critical: 28,
  high: 18,
  medium: 10,
  low: 4,
  info: 1,
}

function clamp(n: number, min = 0, max = 100) {
  return Math.max(min, Math.min(max, Math.round(n)))
}

function postureSubScore(recon: ReconOutput, signals?: ScanSignals): { score: number; reason: string } {
  let score = 72
  const notes: string[] = []

  if (signals?.usesHttpOnly) {
    score -= 35
    notes.push('cleartext HTTP observed')
  } else if (signals?.usesHttps) {
    score += 8
    if (signals.hstsPresent) {
      score += 10
      notes.push('HTTPS + HSTS observed')
    } else {
      score -= 8
      notes.push('HTTPS without HSTS')
    }
  } else {
    const hasTls = recon.findings.some((f) => /tls|https|hsts/i.test(f.signal + f.detail))
    if (!hasTls) {
      score -= 18
      notes.push('transport not confirmed')
    }
  }

  const hasCsp = signals?.hasCsp ?? recon.findings.some((f) => /csp|content-security/i.test(f.signal + f.detail))
  if (!hasCsp) {
    score -= 12
    notes.push('CSP not observed')
  } else {
    score += 6
  }

  const hasHeaders =
    signals?.hasSecurityHeaders ??
    recon.findings.some((f) => /header|x-frame|x-content|hsts/i.test(f.signal + f.detail))
  if (hasHeaders) score += 5
  else {
    score -= 8
    notes.push('protective headers weak')
  }

  const criticalFindings = recon.findings.filter((f) => f.severity === 'critical' || f.severity === 'high').length
  if (criticalFindings > 0) score -= criticalFindings * 7

  return {
    score: clamp(score),
    reason: notes.length ? notes.join('; ') : 'Baseline from observable transport and headers',
  }
}

function findingsSubScore(vulnerabilities: Vulnerability[], coveragePercent = 37): { score: number; reason: string } {
  if (!vulnerabilities.length) {
    const neutral = clamp(58 + Math.round(coveragePercent * 0.1))
    return {
      score: neutral,
      reason: 'No material findings in risk pass — score neutral (not “secure”), coverage-limited',
    }
  }

  let penalty = 0
  for (const v of vulnerabilities) {
    const base = SEVERITY_PENALTY[v.severity] ?? 5
    const exploit = (v.exploitability ?? 5) / 10
    const likelihood = (v.likelihood ?? 5) / 10
    const priority = (v.priority ?? 5) / 10
    penalty += base * (0.5 + 0.25 * exploit + 0.15 * likelihood + 0.1 * priority)
  }

  const capped = Math.min(penalty, 85)
  const top = vulnerabilities.slice().sort((a, b) => (b.priority ?? 0) - (a.priority ?? 0))[0]
  return {
    score: clamp(100 - capped),
    reason: top ? `Driven by "${top.title}" (${top.severity})` : 'Weighted by severity',
  }
}

function attackPathsSubScore(paths: SimulatedAttackPath[]): { score: number; reason: string } {
  if (!paths.length) return { score: 62, reason: 'No evidence-supported paths — neutral' }

  const risks = paths.map((p) => {
    const l = p.likelihood ?? 5
    const i = p.impact ?? 5
    const d = p.difficulty ?? 5
    return (l * i) / Math.max(1, d)
  })
  const worst = Math.max(...risks)
  const score = clamp(100 - worst * 2.2)
  const worstPath = paths.find(
    (p) => (p.likelihood ?? 5) * (p.impact ?? 5) === Math.max(...paths.map((x) => (x.likelihood ?? 5) * (x.impact ?? 5))),
  )

  return {
    score,
    reason: worstPath ? `Worst path: ${worstPath.name}` : `Peak path risk ${worst.toFixed(1)}`,
  }
}

function exposureSubScore(recon: ReconOutput): { score: number; reason: string } {
  const surface = recon.attackSurface?.length ?? 0
  const tech = recon.technologies?.length ?? 0
  const zones = recon.exposureZones?.length ?? 0

  let score = 88
  score -= Math.min(surface * 2.5, 35)
  score -= Math.min(Math.max(tech - 4, 0) * 3, 20)
  score -= zones * 4

  return {
    score: clamp(score),
    reason: `${surface} surface entries · ${tech} technologies`,
  }
}

export type WeightedScoreResult = {
  score: number
  breakdown: ScoreBreakdownItem[]
}

export function computeWeightedScore(input: {
  recon: ReconOutput
  vulnerabilities: Vulnerability[]
  simulatedPaths: SimulatedAttackPath[]
  signals?: ScanSignals
  coveragePercent?: number
}): WeightedScoreResult {
  const coverage = input.coveragePercent ?? 37
  const posture = postureSubScore(input.recon, input.signals)
  const findings = findingsSubScore(input.vulnerabilities, coverage)
  const paths = attackPathsSubScore(input.simulatedPaths)
  const exposure = exposureSubScore(input.recon)

  const components = [
    { category: 'Observed controls', weight: SCORE_WEIGHTS.posture, ...posture },
    { category: 'Weaknesses', weight: SCORE_WEIGHTS.findings, ...findings },
    { category: 'Attack paths', weight: SCORE_WEIGHTS.attackPaths, ...paths },
    { category: 'Exposure', weight: SCORE_WEIGHTS.exposure, ...exposure },
  ]

  const breakdown: ScoreBreakdownItem[] = components.map((c) => ({
    category: c.category,
    weight: c.weight,
    subScore: c.score,
    contribution: Math.round(c.weight * c.score * 10) / 10,
    reason: c.reason,
  }))

  const score = clamp(breakdown.reduce((sum, b) => sum + b.contribution, 0))

  return { score, breakdown }
}

export function scoreToGrade(score: number): 'S' | 'A' | 'B' | 'C' | 'D' {
  if (score >= 90) return 'S'
  if (score >= 80) return 'A'
  if (score >= 70) return 'B'
  if (score >= 55) return 'C'
  return 'D'
}

export function gradeColor(grade: string): string {
  switch (grade) {
    case 'S':
      return '#9fef00'
    case 'A':
      return '#7ee787'
    case 'B':
      return '#f0c040'
    case 'C':
      return '#ff9f43'
    default:
      return '#ff6b6b'
  }
}

export function riskLevelFromScore(score: number): 'Critical' | 'High' | 'Medium' | 'Low' | 'Minimal' {
  if (score < 55) return 'Critical'
  if (score < 70) return 'High'
  if (score < 80) return 'Medium'
  if (score < 90) return 'Low'
  return 'Minimal'
}
