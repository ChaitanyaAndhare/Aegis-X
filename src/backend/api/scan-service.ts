/**
 * Backend API Service — orchestrates Extract → Transform → Load
 */

import type { ScanRequest, ScanResult } from '../core/types'
import { executeEtlPipeline } from '../etl/pipeline'
import { getScanById, listScans } from '../load/scan-repository'

export class ScanService {
  async executeScan(request: ScanRequest): Promise<ScanResult> {
    return executeEtlPipeline({
      targetUrl: request.targetUrl,
      orgType: request.orgType,
      scanDepth: request.scanDepth,
    })
  }

  getScan(scanId: string): ScanResult | null {
    return getScanById(scanId)
  }

  listHistory(): ScanResult[] {
    return listScans()
  }
}

export function createScanService(): ScanService {
  return new ScanService()
}
