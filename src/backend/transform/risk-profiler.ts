/**
 * Task 3: Context-Aware Risk Profiler & Schema
 * Maps base severity to contextual severity based on organization type and data profile
 */

import { OrgType, Severity, SecurityFinding, AssetInventory } from '../core/types';

export interface RiskProfileConfig {
  orgType: OrgType;
  severityMultipliers: Record<Severity, number>;
  complianceRequirements: {
    pciDss: boolean;
    soc2: boolean;
    gdpr: boolean;
    hipaa: boolean;
  };
  sensitiveDataTypes: string[];
  riskFactors: {
    authentication: number;
    paymentProcessing: number;
    personalData: number;
    healthData: number;
  };
}

const RISK_PROFILES: Record<OrgType, RiskProfileConfig> = {
  Fintech: {
    orgType: 'Fintech',
    severityMultipliers: {
      CRITICAL: 1.5,
      HIGH: 1.4,
      MEDIUM: 1.3,
      LOW: 1.2,
      INFO: 1.0
    },
    complianceRequirements: {
      pciDss: true,
      soc2: true,
      gdpr: true,
      hipaa: false
    },
    sensitiveDataTypes: ['financial', 'payment', 'authentication', 'personal'],
    riskFactors: {
      authentication: 1.5,
      paymentProcessing: 1.5,
      personalData: 1.3,
      healthData: 1.0
    }
  },
  Healthcare: {
    orgType: 'Healthcare',
    severityMultipliers: {
      CRITICAL: 1.5,
      HIGH: 1.4,
      MEDIUM: 1.3,
      LOW: 1.2,
      INFO: 1.0
    },
    complianceRequirements: {
      pciDss: false,
      soc2: true,
      gdpr: true,
      hipaa: true
    },
    sensitiveDataTypes: ['health', 'personal', 'authentication'],
    riskFactors: {
      authentication: 1.4,
      paymentProcessing: 1.2,
      personalData: 1.4,
      healthData: 1.5
    }
  },
  SaaS: {
    orgType: 'SaaS',
    severityMultipliers: {
      CRITICAL: 1.3,
      HIGH: 1.2,
      MEDIUM: 1.1,
      LOW: 1.0,
      INFO: 1.0
    },
    complianceRequirements: {
      pciDss: false,
      soc2: true,
      gdpr: true,
      hipaa: false
    },
    sensitiveDataTypes: ['authentication', 'personal', 'business'],
    riskFactors: {
      authentication: 1.3,
      paymentProcessing: 1.2,
      personalData: 1.2,
      healthData: 1.0
    }
  },
  Startup: {
    orgType: 'Startup',
    severityMultipliers: {
      CRITICAL: 1.2,
      HIGH: 1.1,
      MEDIUM: 1.0,
      LOW: 1.0,
      INFO: 1.0
    },
    complianceRequirements: {
      pciDss: false,
      soc2: false,
      gdpr: false,
      hipaa: false
    },
    sensitiveDataTypes: ['authentication', 'personal'],
    riskFactors: {
      authentication: 1.2,
      paymentProcessing: 1.1,
      personalData: 1.1,
      healthData: 1.0
    }
  },
  Ecommerce: {
    orgType: 'Ecommerce',
    severityMultipliers: {
      CRITICAL: 1.4,
      HIGH: 1.3,
      MEDIUM: 1.2,
      LOW: 1.1,
      INFO: 1.0
    },
    complianceRequirements: {
      pciDss: true,
      soc2: true,
      gdpr: true,
      hipaa: false
    },
    sensitiveDataTypes: ['payment', 'personal', 'authentication'],
    riskFactors: {
      authentication: 1.3,
      paymentProcessing: 1.5,
      personalData: 1.3,
      healthData: 1.0
    }
  },
  Government: {
    orgType: 'Government',
    severityMultipliers: {
      CRITICAL: 1.5,
      HIGH: 1.4,
      MEDIUM: 1.3,
      LOW: 1.2,
      INFO: 1.0
    },
    complianceRequirements: {
      pciDss: false,
      soc2: true,
      gdpr: true,
      hipaa: false
    },
    sensitiveDataTypes: ['personal', 'authentication', 'classified'],
    riskFactors: {
      authentication: 1.5,
      paymentProcessing: 1.2,
      personalData: 1.4,
      healthData: 1.0
    }
  }
};

export class RiskProfiler {
  private profile: RiskProfileConfig;

  constructor(orgType: OrgType) {
    this.profile = RISK_PROFILES[orgType];
  }

  /**
   * Calculate contextual severity based on base severity and organization risk profile
   */
  calculateContextualSeverity(
    baseSeverity: Severity,
    finding: SecurityFinding,
    inventory: AssetInventory
  ): Severity {
    const multiplier = this.profile.severityMultipliers[baseSeverity];
    
    // Apply context-specific adjustments
    let adjustedScore = this.severityToScore(baseSeverity) * multiplier;

    // Escalate for authentication-related findings
    if (this.isAuthenticationRelated(finding)) {
      adjustedScore *= this.profile.riskFactors.authentication;
    }

    // Escalate for payment-related findings
    if (this.isPaymentRelated(finding, inventory)) {
      adjustedScore *= this.profile.riskFactors.paymentProcessing;
    }

    // Escalate for personal data-related findings
    if (this.isPersonalDataRelated(finding)) {
      adjustedScore *= this.profile.riskFactors.personalData;
    }

    // Escalate for health data in healthcare orgs
    if (this.profile.orgType === 'Healthcare' && this.isHealthDataRelated(finding)) {
      adjustedScore *= this.profile.riskFactors.healthData;
    }

    return this.scoreToSeverity(adjustedScore);
  }

  /**
   * Apply contextual severity to all findings
   */
  applyContextualSeverity(
    findings: SecurityFinding[],
    inventory: AssetInventory
  ): SecurityFinding[] {
    return findings.map(finding => ({
      ...finding,
      contextualSeverity: this.calculateContextualSeverity(
        finding.baseSeverity,
        finding,
        inventory
      )
    }));
  }

  /**
   * Get compliance requirements for the organization
   */
  getComplianceRequirements() {
    return this.profile.complianceRequirements;
  }

  /**
   * Check if a finding is authentication-related
   */
  private isAuthenticationRelated(finding: SecurityFinding): boolean {
    const authKeywords = [
      'cookie', 'session', 'authentication', 'login', 'csrf',
      'samesite', 'httponly', 'secure', 'authorization'
    ];
    const titleLower = finding.title.toLowerCase();
    return authKeywords.some(keyword => titleLower.includes(keyword));
  }

  /**
   * Check if a finding is payment-related
   */
  private isPaymentRelated(finding: SecurityFinding, inventory: AssetInventory): boolean {
    const paymentKeywords = ['payment', 'stripe', 'credit card', 'pci'];
    const titleLower = finding.title.toLowerCase();
    
    if (paymentKeywords.some(keyword => titleLower.includes(keyword))) {
      return true;
    }

    // Check if inventory has payment technologies
    const hasPaymentTech = inventory.technologies.some(
      tech => tech.name.toLowerCase().includes('stripe') || 
              tech.name.toLowerCase().includes('payment')
    );

    return hasPaymentTech && this.isAuthenticationRelated(finding);
  }

  /**
   * Check if a finding is personal data-related
   */
  private isPersonalDataRelated(finding: SecurityFinding): boolean {
    const personalDataKeywords = ['personal', 'data', 'privacy', 'gdpr', 'pii'];
    const titleLower = finding.title.toLowerCase();
    return personalDataKeywords.some(keyword => titleLower.includes(keyword));
  }

  /**
   * Check if a finding is health data-related
   */
  private isHealthDataRelated(finding: SecurityFinding): boolean {
    const healthKeywords = ['health', 'medical', 'phi', 'hipaa'];
    const titleLower = finding.title.toLowerCase();
    return healthKeywords.some(keyword => titleLower.includes(keyword));
  }

  /**
   * Convert severity to numeric score
   */
  private severityToScore(severity: Severity): number {
    const scores: Record<Severity, number> = {
      CRITICAL: 5,
      HIGH: 4,
      MEDIUM: 3,
      LOW: 2,
      INFO: 1
    };
    return scores[severity];
  }

  /**
   * Convert numeric score to severity
   */
  private scoreToSeverity(score: number): Severity {
    if (score >= 4.5) return 'CRITICAL';
    if (score >= 3.5) return 'HIGH';
    if (score >= 2.5) return 'MEDIUM';
    if (score >= 1.5) return 'LOW';
    return 'INFO';
  }

  /**
   * Get the risk profile configuration
   */
  getProfile(): RiskProfileConfig {
    return this.profile;
  }
}

/**
 * Factory function to create a risk profiler
 */
export function createRiskProfiler(orgType: OrgType): RiskProfiler {
  return new RiskProfiler(orgType);
}
