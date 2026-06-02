import type { ReconOutput, SimulatedAttackPath, Vulnerability } from '../types'

export type AttackabilityRadar = {
  attackability: number
  hardening: number
  exposure: number
  architectureComplexity: number
  dependencyRisk: number
  operationalSecurity: number
  identitySecurity: number
  clientSecurity: number
}

export type AttackabilityLabel = 'Critical' | 'High' | 'Moderate' | 'Low' | 'Very Low'

function clamp(n: number, min = 0, max = 100) {
  return Math.max(min, Math.min(max, Math.round(n)))
}

export function computeRadar(input: {
  recon: ReconOutput
  vulnerabilities: Vulnerability[]
  simulatedPaths: SimulatedAttackPath[]
  securityScore: number
}): AttackabilityRadar {
  const { recon, vulnerabilities, simulatedPaths, securityScore } = input
  const surface = recon.attackSurface?.length ?? 0
  const techCount = recon.technologies?.length ?? 0
  const hasTls = recon.findings.some((f) => /tls|transport|hsts|encryption/i.test(f.signal + f.detail))
  const hasCsp = recon.findings.some((f) => /csp/i.test(f.signal + f.detail))
  const hasHeaders = recon.findings.some((f) => /x-frame|x-content|header/i.test(f.signal + f.detail))
  const hasAuth = recon.findings.some((f) => /auth|session|cookie|oauth/i.test(f.signal + f.detail))
  const critCount = vulnerabilities.filter((v) => v.severity === 'critical' || v.severity === 'high').length
  const pathRisk =
    simulatedPaths.length > 0
      ? Math.max(...simulatedPaths.map((p) => ((p.likelihood ?? 5) * (p.impact ?? 5)) / Math.max(1, p.difficulty ?? 5)))
      : 0

  return {
    attackability: clamp(20 + surface * 3 + critCount * 8 + pathRisk * 2),
    hardening: clamp((hasTls ? 25 : 0) + (hasCsp ? 25 : 0) + (hasHeaders ? 20 : 0) + securityScore * 0.3),
    exposure: clamp(surface * 4 + (recon.exposureZones?.length ?? 0) * 10),
    architectureComplexity: clamp(techCount * 8 + surface * 2),
    dependencyRisk: clamp(techCount * 6 + (recon.attackSurface?.filter((s) => /cdn|npm|bundle|js/i.test(s)).length ?? 0) * 5),
    operationalSecurity: clamp(hasHeaders && hasTls ? 70 : 40),
    identitySecurity: clamp(hasAuth ? 55 : 30),
    clientSecurity: clamp(hasCsp ? 65 : 35),
  }
}

export function computeAttackabilityIndex(
  radar: AttackabilityRadar,
  securityScore: number,
): { index: number; label: AttackabilityLabel } {
  const raw =
    radar.attackability * 0.35 +
    radar.exposure * 0.25 +
    radar.dependencyRisk * 0.15 +
    (100 - radar.hardening) * 0.15 +
    (100 - securityScore) * 0.1
  const index = clamp(raw)
  const label: AttackabilityLabel =
    index >= 80 ? 'Critical' : index >= 65 ? 'High' : index >= 45 ? 'Moderate' : index >= 25 ? 'Low' : 'Very Low'
  return { index, label }
}
