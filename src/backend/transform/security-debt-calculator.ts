/**
 * Security Debt Calculator
 * Implements a dynamic risk engine that weights vulnerabilities based on Contextual Risk Profile Matrix
 */

import { SecurityFinding, SecurityDebtScore, Severity, OrgType } from '../core/types';
import { RiskProfiler } from './risk-profiler';

export interface SecurityDebtConfig {
  severityWeights: Record<Severity, number>;
  complianceWeights: {
    pciDss: number;
    soc2: number;
    gdpr: number;
    hipaa: number;
  };
  trendWindow: number; // number of scans to consider for trend
}

const DEFAULT_CONFIG: SecurityDebtConfig = {
  severityWeights: {
    CRITICAL: 25,
    HIGH: 15,
    MEDIUM: 8,
    LOW: 3,
    INFO: 1
  },
  complianceWeights: {
    pciDss: 1.2,
    soc2: 1.1,
    gdpr: 1.1,
    hipaa: 1.3
  },
  trendWindow: 5
};

export class SecurityDebtCalculator {
  private config: SecurityDebtConfig;
  private riskProfiler: RiskProfiler;
  private historicalScores: number[] = [];

  constructor(orgType: OrgType, config?: Partial<SecurityDebtConfig>) {
    this.config = { ...DEFAULT_CONFIG, ...config };
    this.riskProfiler = new RiskProfiler(orgType);
  }

  /**
   * Calculate security debt score from findings
   * Returns a score from 0-100 (higher = more debt)
   */
  calculateSecurityDebt(findings: SecurityFinding[]): SecurityDebtScore {
    const severityCounts = this.calculateSeverityCounts(findings);
    const totalScore = this.calculateTotalScore(severityCounts);
    const complianceFlags = this.checkCompliance(findings);
    const trend = this.calculateTrend();

    return {
      totalScore,
      criticalCount: severityCounts.CRITICAL,
      highCount: severityCounts.HIGH,
      mediumCount: severityCounts.MEDIUM,
      lowCount: severityCounts.LOW,
      infoCount: severityCounts.INFO,
      trend,
      complianceFlags
    };
  }

  /**
   * Calculate severity counts from findings
   */
  private calculateSeverityCounts(findings: SecurityFinding[]): Record<Severity, number> {
    const counts: Record<Severity, number> = {
      CRITICAL: 0,
      HIGH: 0,
      MEDIUM: 0,
      LOW: 0,
      INFO: 0
    };

    for (const finding of findings) {
      counts[finding.contextualSeverity]++;
    }

    return counts;
  }

  /**
   * Calculate total security debt score
   * Uses weighted sum of findings, adjusted by compliance requirements
   */
  private calculateTotalScore(severityCounts: Record<Severity, number>): number {
    let rawScore = 0;

    for (const [severity, count] of Object.entries(severityCounts)) {
      rawScore += count * this.config.severityWeights[severity as Severity];
    }

    // Apply compliance multiplier
    const compliance = this.riskProfiler.getComplianceRequirements();
    let complianceMultiplier = 1.0;

    if (compliance.pciDss) complianceMultiplier *= this.config.complianceWeights.pciDss;
    if (compliance.soc2) complianceMultiplier *= this.config.complianceWeights.soc2;
    if (compliance.gdpr) complianceMultiplier *= this.config.complianceWeights.gdpr;
    if (compliance.hipaa) complianceMultiplier *= this.config.complianceWeights.hipaa;

    const adjustedScore = rawScore * complianceMultiplier;

    // Normalize to 0-100
    return Math.min(Math.round(adjustedScore), 100);
  }

  /**
   * Check compliance flags based on findings
   */
  private checkCompliance(findings: SecurityFinding[]): SecurityDebtScore['complianceFlags'] {
    const compliance = this.riskProfiler.getComplianceRequirements();

    // Check for critical/high findings that would violate compliance
    const criticalOrHigh = findings.filter(
      f => f.contextualSeverity === 'CRITICAL' || f.contextualSeverity === 'HIGH'
    );

    // PCI-DSS compliance check
    const pciDssCompliant = compliance.pciDss 
      ? criticalOrHigh.filter(f => f.ruleId.startsWith('SEC-') || f.ruleId.startsWith('COOKIE-')).length === 0
      : true;

    // SOC2 compliance check
    const soc2Compliant = compliance.soc2
      ? criticalOrHigh.filter(f => f.contextualSeverity === 'CRITICAL').length === 0
      : true;

    // GDPR compliance check
    const gdprCompliant = compliance.gdpr
      ? criticalOrHigh.filter(f => f.ruleId.startsWith('COOKIE-') || f.ruleId.startsWith('INFO-')).length === 0
      : true;

    // HIPAA compliance check
    const hipaaCompliant = compliance.hipaa
      ? criticalOrHigh.filter(f => f.contextualSeverity === 'CRITICAL').length === 0
      : true;

    return {
      pciDss: pciDssCompliant,
      soc2: soc2Compliant,
      gdpr: gdprCompliant,
      hipaa: hipaaCompliant
    };
  }

  /**
   * Calculate trend based on historical scores
   */
  private calculateTrend(): 'improving' | 'degrading' | 'stable' {
    if (this.historicalScores.length < 2) {
      return 'stable';
    }

    const recentScores = this.historicalScores.slice(-this.config.trendWindow);
    const averageRecent = recentScores.reduce((a, b) => a + b, 0) / recentScores.length;
    const previousAverage = this.historicalScores.slice(-this.config.trendWindow - 1, -1)
      .reduce((a, b) => a + b, 0) / (recentScores.length - 1);

    const difference = previousAverage - averageRecent;

    if (difference > 5) {
      return 'improving';
    } else if (difference < -5) {
      return 'degrading';
    } else {
      return 'stable';
    }
  }

  /**
   * Add a historical score for trend calculation
   */
  addHistoricalScore(score: number): void {
    this.historicalScores.push(score);
    
    // Keep only the most recent scores
    if (this.historicalScores.length > this.config.trendWindow * 2) {
      this.historicalScores = this.historicalScores.slice(-this.config.trendWindow * 2);
    }
  }

  /**
   * Get historical scores
   */
  getHistoricalScores(): number[] {
    return [...this.historicalScores];
  }

  /**
   * Reset historical scores
   */
  resetHistoricalScores(): void {
    this.historicalScores = [];
  }

  /**
   * Calculate priority recommendations based on security debt
   */
  calculateRecommendations(debtScore: SecurityDebtScore): string[] {
    const recommendations: string[] = [];

    if (debtScore.criticalCount > 0) {
      recommendations.push(`Address ${debtScore.criticalCount} critical vulnerabilities immediately - these pose the highest risk.`);
    }

    if (debtScore.highCount > 5) {
      recommendations.push(`Reduce ${debtScore.highCount} high-severity findings to improve security posture.`);
    }

    if (!debtScore.complianceFlags.pciDss) {
      recommendations.push('PCI-DSS compliance violations detected - review security headers and cookie configurations.');
    }

    if (!debtScore.complianceFlags.soc2) {
      recommendations.push('SOC2 compliance violations detected - address critical findings to meet compliance requirements.');
    }

    if (!debtScore.complianceFlags.gdpr) {
      recommendations.push('GDPR compliance violations detected - review cookie and data protection measures.');
    }

    if (!debtScore.complianceFlags.hipaa) {
      recommendations.push('HIPAA compliance violations detected - address critical findings to protect health data.');
    }

    if (debtScore.trend === 'degrading') {
      recommendations.push('Security posture is degrading - implement a remediation plan to reverse the trend.');
    }

    if (debtScore.totalScore > 75) {
      recommendations.push('Security debt is high - prioritize security remediation in upcoming sprints.');
    }

    if (recommendations.length === 0) {
      recommendations.push('Security posture is good - continue regular monitoring and maintenance.');
    }

    return recommendations;
  }
}

/**
 * Factory function to create a security debt calculator
 */
export function createSecurityDebtCalculator(
  orgType: OrgType,
  config?: Partial<SecurityDebtConfig>
): SecurityDebtCalculator {
  return new SecurityDebtCalculator(orgType, config);
}
