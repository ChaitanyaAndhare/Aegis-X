import type { RuleFinding } from './types'

const EFFORT: Record<string, 'Low' | 'Medium' | 'High'> = {
  missing_csp: 'Low',
  missing_hsts: 'Low',
  missing_x_frame: 'Low',
  missing_xcto: 'Low',
  insecure_transport: 'Medium',
  cookie_secure_missing: 'Low',
  cookie_httponly_missing: 'Low',
  server_disclosure: 'Low',
  exposed_api: 'Medium',
  login_surface: 'Medium',
}

const REDUCTION: Record<string, number> = {
  critical: 18,
  high: 14,
  medium: 10,
  low: 5,
  info: 2,
}

export function buildRoadmap(findings: RuleFinding[]) {
  return findings
    .map((f, i) => ({
      priority: i + 1,
      fix: f.recommendedFix,
      effort: EFFORT[f.weaknessId] ?? 'Medium',
      riskReductionPercent: REDUCTION[f.severity] ?? 8,
    }))
    .sort((a, b) => b.riskReductionPercent - a.riskReductionPercent)
    .map((item, i) => ({ ...item, priority: i + 1 }))
}
