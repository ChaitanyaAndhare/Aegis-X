import type { IntelligenceReport } from './types'

export function isIntelligenceReport(report: unknown): report is IntelligenceReport {
  const r = report as IntelligenceReport
  return (
    typeof report === 'object' &&
    report !== null &&
    'threatModel' in report &&
    'executiveV2' in report &&
    (!!r.platform?.findings?.length || !!r.digitalTwin?.nodes?.length || !!r.vulnerabilities?.length)
  )
}

export function isLegacyScannerReport(report: unknown): boolean {
  return (
    typeof report === 'object' &&
    report !== null &&
    'securityScore' in report &&
    'vulnerabilities' in report &&
    !isIntelligenceReport(report)
  )
}
