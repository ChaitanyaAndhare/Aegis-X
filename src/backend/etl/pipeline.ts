/**
 * Deterministic Security ETL: Extract → Transform → Load
 */

import { v4 as uuidv4 } from 'uuid'
import type { OrgType, ScanRequest, ScanResult } from '../core/types'
import { ScanWorker } from '../extract/scan-worker'
import { calculateScanDelta } from '../load/diff-engine'
import { getPreviousScanForTarget, persistScanResult } from '../load/scan-repository'
import { RulesEngine } from '../rules'
import { RiskProfiler } from '../transform/risk-profiler'
import { SecurityDebtCalculator } from '../transform/security-debt-calculator'

export const ETL_PIPELINE_STEPS = ['extract', 'transform', 'risk', 'load', 'delta'] as const
export type EtlPipelineStep = (typeof ETL_PIPELINE_STEPS)[number]

const rulesEngine = new RulesEngine()

export function parseOrgTypeFromDescription(description: string): OrgType {
  const match = description.match(/\[orgType:\s*([A-Za-z]+)\]/i)
  const candidate = match?.[1]
  const allowed: OrgType[] = ['Fintech', 'Healthcare', 'SaaS', 'Startup', 'Ecommerce', 'Government']
  if (candidate && allowed.includes(candidate as OrgType)) {
    return candidate as OrgType
  }
  return 'SaaS'
}

export function formatOrgTypeTag(orgType: OrgType): string {
  return `[orgType: ${orgType}]`
}

export async function executeEtlPipeline(opts: {
  targetUrl: string
  orgType: OrgType
  scanDepth?: ScanRequest['scanDepth']
  onStep?: (step: EtlPipelineStep, detail: Record<string, unknown>) => void
}): Promise<ScanResult> {
  const scanId = uuidv4()
  const startTime = Date.now()
  const request: ScanRequest = {
    targetUrl: opts.targetUrl,
    orgType: opts.orgType,
    scanDepth: opts.scanDepth ?? 'standard',
  }

  try {
    opts.onStep?.('extract', { targetUrl: request.targetUrl })
    const worker = new ScanWorker()
    const assetInventory = await worker.scan(request)

    opts.onStep?.('transform', { endpoints: assetInventory.endpoints.length })
    const rawFindings = rulesEngine.execute(assetInventory)

    opts.onStep?.('risk', { findings: rawFindings.length })
    const riskProfiler = new RiskProfiler(request.orgType)
    const findings = riskProfiler.applyContextualSeverity(rawFindings, assetInventory)

    const debtCalculator = new SecurityDebtCalculator(request.orgType)
    const securityDebt = debtCalculator.calculateSecurityDebt(findings)

    opts.onStep?.('load', { score: securityDebt.totalScore })
    const previousScan = getPreviousScanForTarget(assetInventory.targetUrl)

    const currentScan: ScanResult = {
      scanId,
      request,
      assetInventory,
      findings,
      securityDebt,
      timestamp: new Date().toISOString(),
      duration: Math.max(1, Math.round((Date.now() - startTime) / 1000)),
      status: 'completed',
    }

    opts.onStep?.('delta', { hasPrevious: Boolean(previousScan) })
    currentScan.delta = calculateScanDelta(previousScan, currentScan)

    if (currentScan.delta) {
      const trend =
        currentScan.delta.resolvedFindings.length > currentScan.delta.newFindings.length
          ? 'improving'
          : currentScan.delta.newFindings.length > currentScan.delta.resolvedFindings.length
            ? 'degrading'
            : 'stable'
      currentScan.securityDebt = { ...currentScan.securityDebt, trend }
    }

    debtCalculator.addHistoricalScore(securityDebt.totalScore)
    await persistScanResult(currentScan)

    return currentScan
  } catch (error) {
    return {
      scanId,
      request,
      assetInventory: {
        targetUrl: request.targetUrl,
        scanId,
        scanTime: new Date().toISOString(),
        orgType: request.orgType,
        technologies: [],
        headers: {},
        cookies: [],
        endpoints: [],
      },
      findings: [],
      securityDebt: {
        totalScore: 0,
        criticalCount: 0,
        highCount: 0,
        mediumCount: 0,
        lowCount: 0,
        infoCount: 0,
        trend: 'stable',
        complianceFlags: { pciDss: true, soc2: true, gdpr: true, hipaa: true },
      },
      timestamp: new Date().toISOString(),
      duration: Math.max(1, Math.round((Date.now() - startTime) / 1000)),
      status: 'failed',
      error: error instanceof Error ? error.message : 'Unknown error',
    }
  }
}
