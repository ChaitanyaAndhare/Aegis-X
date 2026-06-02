import type { Severity } from '../types'
import type { ScanSignals } from './evidence-engine'

export type ConfidenceLevel = 'High' | 'Medium' | 'Low'
export type ControlStatus = 'Excellent' | 'Good' | 'Fair' | 'Poor'
export type ImpactLevel = 'Low' | 'Medium' | 'High'

export type VerificationStatus = 'verified' | 'potential' | 'observed'

export type EvidenceFinding = {
  id: string
  title: string
  severity: Severity
  confidenceScore: number
  confidenceLevel: ConfidenceLevel
  /** Observed facts only */
  facts: string[]
  /** Hypotheses — not directly observed */
  inferences: string[]
  evidence: string
  observedSignal: string
  reasoning: string
  potentialImpact: string
  recommendedFix: string
  affectedAssets: string[]
  priority: number
  cwe?: string
  verificationStatus?: VerificationStatus
  reproductionSteps?: string[]
  testPayload?: string
  checkId?: string
  category?: string
}

export type ExposureNodeType = 'Asset' | 'Weakness' | 'Threat' | 'Control' | 'Impact'
export type ExposureRelation = 'EXPOSES' | 'ENABLES' | 'IMPACTS' | 'MITIGATED_BY'

export type ThreatExposureNode = {
  id: string
  label: string
  type: ExposureNodeType
  description: string
  evidence?: string
  confidence?: number
  affectedAssets?: string[]
  relatedFindings?: string[]
}

export type ThreatExposureEdge = {
  id: string
  source: string
  target: string
  relation: ExposureRelation
  evidence?: string
  reasoning?: string
  confidence?: number
  impact?: string
}

export type AttackPathRecord = {
  id: string
  name: string
  steps: string[]
  likelihood: number
  impact: number
  complexity: number
  confidence: number
  businessRisk: string
  evidenceNote?: string
}

export type CoverageArea = {
  id: string
  label: string
  assessed: boolean
  note?: string
}

export type EvidenceCoverage = {
  percent: number
  areas: CoverageArea[]
}

export type AssessmentConfidence = {
  percent: number
  reason: string
}

export type UncertaintyLevel = 'Known' | 'Likely' | 'Possible' | 'Unknown'

export type UncertaintyItem = {
  level: UncertaintyLevel
  statement: string
}

export type ObservedSecurityPosture = {
  summary: string
  label: string
}

export type SecurityDebt = {
  total: number
  contributors: { category: string; score: number }[]
  expectedReduction: number
  topContributors: { category: string; score: number }[]
}

export type ControlDomain = {
  domain: string
  status: ControlStatus
  reasoning: string
}

export type MitreEntry = {
  tactic: string
  technique: string
  techniqueId?: string
  findingId: string
  confidence: number
}

export type BusinessImpactRecord = {
  findingId: string
  title: string
  operational: ImpactLevel
  financial: ImpactLevel
  reputation: ImpactLevel
  data: ImpactLevel
}

export type RemediationItem = {
  priority: number
  fix: string
  effort: 'Low' | 'Medium' | 'High'
  riskReductionPercent: number
  dependencies?: string
}

export type ArchitectureThreatModel = {
  assets: { name: string; type: string; exposure: string }[]
  trustBoundaries: { name: string; description: string }[]
  entryPoints: string[]
  threats: { name: string; asset: string; severity: string }[]
  controls: { name: string; status: ControlStatus }[]
  missingControls: string[]
}

export type BenchmarkSegment = 'Modern SaaS' | 'Enterprise' | 'Startup' | 'Open Source'

export type BenchmarkResult = {
  segment: BenchmarkSegment
  percentile: number
  relativeRisk: 'Below Average' | 'Average' | 'Above Average'
  maturity: string
}

export type TechnicalProfile = {
  frameworks: string[]
  authProviders: string[]
  hosting: string[]
  exploitFocusAreas: string[]
}

export type PlatformIntelligence = {
  technicalProfile: TechnicalProfile
  riskScore: number
  rawRiskScore?: number
  grade: string
  riskLevel: string
  evidenceCoverage: EvidenceCoverage
  assessmentConfidence: AssessmentConfidence
  observedPosture: ObservedSecurityPosture
  uncertainty: UncertaintyItem[]
  scanSignals: ScanSignals
  attackabilityIndex: number
  attackabilityLabel: string
  securityDebt: SecurityDebt
  controlCoverage: ControlDomain[]
  controlCoveragePercent: number
  securityPosture: string
  architectureProfile: string
  findings: EvidenceFinding[]
  topFindings: EvidenceFinding[]
  topThreats: { id: string; name: string; severity: string; description: string }[]
  topAttackPaths: AttackPathRecord[]
  threatExposureGraph: { nodes: ThreatExposureNode[]; edges: ThreatExposureEdge[] }
  attackPaths: AttackPathRecord[]
  architectureModel: ArchitectureThreatModel
  mitreMapping: MitreEntry[]
  businessImpacts: BusinessImpactRecord[]
  remediationRoadmap: RemediationItem[]
  benchmarking: BenchmarkResult[]
  scanDurationMs?: number
  githubInsights: string[]
}
