/**
 * Task 4: Historical Diff Engine
 * Pure function to calculate scan deltas between previous and current scans
 */

import { SecurityFinding, AssetInventory, ScanDelta, ScanResult } from '../core/types';

/**
 * Compare two security findings to determine if they are the same issue
 * Uses ruleId, title, and location for comparison
 */
function findingsMatch(a: SecurityFinding, b: SecurityFinding): boolean {
  return (
    a.ruleId === b.ruleId &&
    a.title === b.title &&
    a.evidence.location === b.evidence.location
  );
}

/**
 * Compare two asset inventories to determine if they represent the same asset
 * Uses targetUrl for comparison
 */
function assetsMatch(a: AssetInventory, b: AssetInventory): boolean {
  return a.targetUrl === b.targetUrl;
}

/**
 * Calculate the delta between two scans
 * Returns new findings, resolved findings, stable findings, new assets, and removed assets
 */
export function calculateScanDelta(
  previousScan: ScanResult | null,
  currentScan: ScanResult
): ScanDelta {
  const newFindings: SecurityFinding[] = [];
  const resolvedFindings: SecurityFinding[] = [];
  const stableFindings: SecurityFinding[] = [];
  const newAssets: AssetInventory[] = [];
  const removedAssets: AssetInventory[] = [];

  // If there's no previous scan, everything is new
  if (!previousScan) {
    return {
      newFindings: currentScan.findings,
      resolvedFindings: [],
      stableFindings: [],
      newAssets: [currentScan.assetInventory],
      removedAssets: [],
      timestamp: new Date().toISOString()
    };
  }

  // Compare findings
  const previousFindingIds = new Set(previousScan.findings.map(f => f.id));
  const currentFindingIds = new Set(currentScan.findings.map(f => f.id));

  // Find new findings (in current but not in previous)
  for (const currentFinding of currentScan.findings) {
    const isExisting = previousScan.findings.some(prevFinding =>
      findingsMatch(prevFinding, currentFinding)
    );

    if (!isExisting) {
      newFindings.push(currentFinding);
    } else {
      stableFindings.push(currentFinding);
    }
  }

  // Find resolved findings (in previous but not in current)
  for (const previousFinding of previousScan.findings) {
    const isStillPresent = currentScan.findings.some(currentFinding =>
      findingsMatch(previousFinding, currentFinding)
    );

    if (!isStillPresent) {
      resolvedFindings.push(previousFinding);
    }
  }

  // Compare assets
  const previousAssetUrls = new Set(previousScan.assetInventory ? [previousScan.assetInventory.targetUrl] : []);
  const currentAssetUrls = new Set(currentScan.assetInventory ? [currentScan.assetInventory.targetUrl] : []);

  // Find new assets
  if (currentScan.assetInventory && !previousAssetUrls.has(currentScan.assetInventory.targetUrl)) {
    newAssets.push(currentScan.assetInventory);
  }

  // Find removed assets
  if (previousScan.assetInventory && !currentAssetUrls.has(previousScan.assetInventory.targetUrl)) {
    removedAssets.push(previousScan.assetInventory);
  }

  return {
    newFindings,
    resolvedFindings,
    stableFindings,
    newAssets,
    removedAssets,
    timestamp: new Date().toISOString()
  };
}

/**
 * Calculate trend based on delta
 * Returns 'improving', 'degrading', or 'stable'
 */
export function calculateTrend(delta: ScanDelta): 'improving' | 'degrading' | 'stable' {
  const newCount = delta.newFindings.length;
  const resolvedCount = delta.resolvedFindings.length;

  if (resolvedCount > newCount) {
    return 'improving';
  } else if (newCount > resolvedCount) {
    return 'degrading';
  } else {
    return 'stable';
  }
}

/**
 * Calculate severity distribution from findings
 */
export function calculateSeverityDistribution(findings: SecurityFinding[]) {
  return {
    critical: findings.filter(f => f.contextualSeverity === 'CRITICAL').length,
    high: findings.filter(f => f.contextualSeverity === 'HIGH').length,
    medium: findings.filter(f => f.contextualSeverity === 'MEDIUM').length,
    low: findings.filter(f => f.contextualSeverity === 'LOW').length,
    info: findings.filter(f => f.contextualSeverity === 'INFO').length
  };
}

/**
 * Generate a summary of the delta
 */
export function generateDeltaSummary(delta: ScanDelta): string {
  const trend = calculateTrend(delta);
  const newCount = delta.newFindings.length;
  const resolvedCount = delta.resolvedFindings.length;
  const stableCount = delta.stableFindings.length;

  let summary = `Scan delta: ${newCount} new findings, ${resolvedCount} resolved, ${stableCount} stable. Trend: ${trend}.`;

  if (delta.newAssets.length > 0) {
    summary += ` ${delta.newAssets.length} new assets discovered.`;
  }

  if (delta.removedAssets.length > 0) {
    summary += ` ${delta.removedAssets.length} assets removed.`;
  }

  return summary;
}

/**
 * Calculate regression risk based on delta
 * Returns a score from 0-100 indicating regression risk
 */
export function calculateRegressionRisk(delta: ScanDelta): number {
  const newCritical = delta.newFindings.filter(f => f.contextualSeverity === 'CRITICAL').length;
  const newHigh = delta.newFindings.filter(f => f.contextualSeverity === 'HIGH').length;
  const resolvedCritical = delta.resolvedFindings.filter(f => f.contextualSeverity === 'CRITICAL').length;
  const resolvedHigh = delta.resolvedFindings.filter(f => f.contextualSeverity === 'HIGH').length;

  // Weight new findings more heavily than resolved findings
  const newWeightedScore = (newCritical * 10) + (newHigh * 5);
  const resolvedWeightedScore = (resolvedCritical * 10) + (resolvedHigh * 5);

  const netScore = newWeightedScore - resolvedWeightedScore;

  // Normalize to 0-100
  return Math.min(Math.max(netScore, 0), 100);
}
