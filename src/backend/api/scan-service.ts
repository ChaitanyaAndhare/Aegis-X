/**
 * Backend API Service
 * Orchestrates the complete ETL pipeline: Extract -> Transform -> Load
 */

import { ScanRequest, ScanResult, AssetInventory, SecurityFinding } from '../core/types';
import { ScanWorker, createScanWorker } from '../extract/scan-worker';
import { RulesEngine } from '../rules';
import { RiskProfiler } from '../transform/risk-profiler';
import { SecurityDebtCalculator } from '../transform/security-debt-calculator';
import { calculateScanDelta } from '../load/diff-engine';
import { v4 as uuidv4 } from 'uuid';

export class ScanService {
  private worker: ScanWorker | null = null;
  private rulesEngine: RulesEngine;
  private previousScan: ScanResult | null = null;

  constructor() {
    this.rulesEngine = new RulesEngine();
  }

  /**
   * Initialize the scan service
   */
  async initialize(): Promise<void> {
    this.worker = await createScanWorker();
  }

  /**
   * Execute a complete scan
   * Extract -> Transform -> Load pipeline
   */
  async executeScan(request: ScanRequest): Promise<ScanResult> {
    if (!this.worker) {
      throw new Error('ScanService not initialized. Call initialize() first.');
    }

    const scanId = uuidv4();
    const startTime = Date.now();

    try {
      // EXTRACT: Scrape and collect data
      const assetInventory = await this.worker.scan(request);

      // TRANSFORM: Apply rules and risk profiling
      const rawFindings = this.rulesEngine.execute(assetInventory);
      const riskProfiler = new RiskProfiler(request.orgType);
      const findings = riskProfiler.applyContextualSeverity(rawFindings, assetInventory);

      // Calculate security debt
      const debtCalculator = new SecurityDebtCalculator(request.orgType);
      const securityDebt = debtCalculator.calculateSecurityDebt(findings);

      // Calculate delta if we have a previous scan
      const currentScan: ScanResult = {
        scanId,
        request,
        assetInventory,
        findings,
        securityDebt,
        timestamp: new Date().toISOString(),
        duration: Math.round((Date.now() - startTime) / 1000),
        status: 'completed'
      };

      // Calculate historical delta
      const delta = calculateScanDelta(this.previousScan, currentScan);
      currentScan.delta = delta;

      // Update historical scores for trend calculation
      debtCalculator.addHistoricalScore(securityDebt.totalScore);

      // Store current scan as previous for next comparison
      this.previousScan = currentScan;

      return currentScan;

    } catch (error) {
      const endTime = Date.now();
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
          endpoints: []
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
          complianceFlags: {
            pciDss: true,
            soc2: true,
            gdpr: true,
            hipaa: true
          }
        },
        timestamp: new Date().toISOString(),
        duration: Math.round((endTime - startTime) / 1000),
        status: 'failed',
        error: error instanceof Error ? error.message : 'Unknown error'
      };
    }
  }

  /**
   * Get the previous scan result
   */
  getPreviousScan(): ScanResult | null {
    return this.previousScan;
  }

  /**
   * Reset the scan service state
   */
  reset(): void {
    this.previousScan = null;
  }

  /**
   * Cleanup resources
   */
  async cleanup(): Promise<void> {
    if (this.worker) {
      await this.worker.cleanup();
      this.worker = null;
    }
  }
}

/**
 * Factory function to create a scan service
 */
export async function createScanService(): Promise<ScanService> {
  const service = new ScanService();
  await service.initialize();
  return service;
}
