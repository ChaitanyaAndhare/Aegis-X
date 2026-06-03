/**
 * Task 2: Pure Heuristic Rules Engine
 * File-based rules database that executes strict logical operations against AssetInventory
 * Every rule must populate SecurityEvidence with literal strings scraped from the target
 */

import { RuleDefinition, AssetInventory, SecurityFinding, Severity } from '../core/types';
import { v4 as uuidv4 } from 'uuid';

// Import all rule modules
import { securityHeaderRules } from './security-headers';
import { cookieRules } from './cookies';
import { contentRules } from './content';
import { infoLeakageRules } from './info-leakage';

export class RulesEngine {
  private rules: RuleDefinition[] = [];

  constructor() {
    this.loadRules();
  }

  private loadRules(): void {
    this.rules = [
      ...securityHeaderRules,
      ...cookieRules,
      ...contentRules,
      ...infoLeakageRules
    ];
  }

  execute(inventory: AssetInventory): SecurityFinding[] {
    const findings: SecurityFinding[] = [];

    for (const rule of this.rules) {
      try {
        const finding = rule.check(inventory);
        if (finding) {
          findings.push(finding);
        }
      } catch (error) {
        console.error(`Error executing rule ${rule.id}:`, error);
      }
    }

    return findings;
  }

  getRules(): RuleDefinition[] {
    return this.rules;
  }

  getRuleById(id: string): RuleDefinition | undefined {
    return this.rules.find(rule => rule.id === id);
  }
}

// Helper function to create security evidence
export function createEvidence(
  location: string,
  rawObserved: string,
  reproduciblePayload?: string
): import('../core/types').SecurityEvidence {
  return {
    timestamp: new Date().toISOString(),
    location,
    rawObserved,
    reproduciblePayload
  };
}

// Helper function to create security finding
export function createFinding(
  rule: RuleDefinition,
  evidence: import('../core/types').SecurityEvidence,
  remediationSteps: string[]
): SecurityFinding {
  return {
    id: uuidv4(),
    ruleId: rule.id,
    title: rule.title,
    description: rule.description,
    baseSeverity: rule.severity,
    contextualSeverity: rule.severity, // Will be adjusted by Risk Profiler
    evidence,
    remediationSteps,
    cweId: rule.cweId
  };
}
