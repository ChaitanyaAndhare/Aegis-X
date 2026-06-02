import type { ReconOutput, SimulatedAttackPath, Vulnerability } from '../types'

const SEV_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }

/** Stable ordering so the same target produces comparable report structure. */
export function normalizeVulnerabilities(vulns: Vulnerability[]): Vulnerability[] {
  return [...vulns]
    .map((v, i) => ({
      ...v,
      id: v.id || `f-${i + 1}`,
      priority: v.priority ?? priorityFromSeverity(v.severity),
    }))
    .sort((a, b) => {
      const sd = (SEV_ORDER[a.severity] ?? 5) - (SEV_ORDER[b.severity] ?? 5)
      if (sd !== 0) return sd
      return (b.priority ?? 0) - (a.priority ?? 0) || a.title.localeCompare(b.title)
    })
    .map((v, i) => ({ ...v, id: `f-${i + 1}` }))
}

function priorityFromSeverity(sev: string): number {
  switch (sev) {
    case 'critical':
      return 10
    case 'high':
      return 8
    case 'medium':
      return 6
    case 'low':
      return 4
    default:
      return 2
  }
}

export function mergeReconOutputs(base: ReconOutput, extra: Partial<ReconOutput>): ReconOutput {
  const findingKeys = new Set(base.findings.map((f) => f.signal.toLowerCase()))
  const mergedFindings = [...base.findings]
  for (const f of extra.findings ?? []) {
    if (!findingKeys.has(f.signal.toLowerCase())) {
      mergedFindings.push(f)
      findingKeys.add(f.signal.toLowerCase())
    }
  }
  return {
    ...base,
    technologies: [...new Set([...base.technologies, ...(extra.technologies ?? [])])],
    attackSurface: [...new Set([...base.attackSurface, ...(extra.attackSurface ?? [])])],
    findings: mergedFindings,
    trustBoundaries: extra.trustBoundaries?.length ? extra.trustBoundaries : base.trustBoundaries,
    infrastructureSignals: [...new Set([...(base.infrastructureSignals ?? []), ...(extra.infrastructureSignals ?? [])])],
  }
}

export function normalizeAttackPaths(paths: SimulatedAttackPath[]): SimulatedAttackPath[] {
  return paths.map((p, i) => ({
    ...p,
    id: p.id || `path-${i + 1}`,
    steps: p.steps.map((s) => s.trim()).filter(Boolean),
  }))
}
