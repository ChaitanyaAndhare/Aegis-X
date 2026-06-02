import type { IntelligenceReport, ReconOutput } from '../types'

export function reconFromReport(report: IntelligenceReport): ReconOutput {
  return {
    technologies: report.technologies,
    attackSurface: report.attackSurface,
    findings:
      report.reconInsights?.infrastructureSignals?.map((s) => ({ signal: s, detail: 'Observed' })) ??
      report.attackSurface.map((s) => ({ signal: s, detail: 'Surface component' })),
    authModel: report.reconInsights?.authModel,
    trustBoundaries: report.reconInsights?.trustBoundaries ?? [],
    exposureZones: report.reconInsights?.exposureZones ?? [],
    infrastructureSignals: report.reconInsights?.infrastructureSignals ?? [],
    dataFlowNotes: report.reconInsights?.dataFlowNotes,
  }
}
