export const GUEST_USER_ID = '00000000-0000-4000-8000-000000000001'

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info'

export type TwinNodeType = 'Website' | 'Technology' | 'Header' | 'Cookie' | 'Route' | 'Dependency' | 'Finding' | 'Threat'

export type TwinRelation = 'USES' | 'EXPOSES' | 'CONNECTS_TO' | 'ENABLES' | 'INCREASES_RISK'

export type DigitalTwinNode = {
  id: string
  type: TwinNodeType
  label: string
  props?: Record<string, string>
}

export type DigitalTwinEdge = {
  id: string
  source: string
  target: string
  relation: TwinRelation
}

export type DigitalTwinGraph = {
  nodes: DigitalTwinNode[]
  edges: DigitalTwinEdge[]
}

export type ReconOutput = {
  technologies: string[]
  attackSurface: string[]
  findings: { signal: string; detail: string; severity?: Severity; category?: string }[]
  authModel?: string
  trustBoundaries?: string[]
  exposureZones?: { zone: string; assets: string[]; risk: string }[]
  infrastructureSignals?: string[]
  dataFlowNotes?: string
}

export type Vulnerability = {
  id: string
  title: string
  severity: Severity
  description: string
  confidence: number
  cwe?: string
  remediation?: string
  impact?: number
  likelihood?: number
  exploitability?: number
  businessCost?: string
  priority?: number
  attackVector?: string
  mitreTactics?: string[]
  prerequisites?: string[]
  detectionDifficulty?: 'low' | 'medium' | 'high'
}

export type AttackPathEdge = { source: string; target: string; label: string }

export type SimulatedAttackPath = {
  id: string
  name: string
  steps: string[]
  likelihood: number
  impact: number
  difficulty: number
  rank: number
  objective?: string
  mitreTechniques?: string[]
}

export type ThreatAttack = {
  name: string
  description: string
  chain: string[]
  confidence: number
  mitreTechniques?: string[]
}

export type ThreatModel = {
  threats: { name: string; description: string; severity: string; strideCategory?: string }[]
  attackChains: ThreatAttack[]
  businessImpact: string[]
  confidence: number
  mostLikely: ThreatAttack
  mostDangerous: ThreatAttack
  mostRealistic: ThreatAttack
  adversaryPersonas?: { name: string; objective: string; capability: string }[]
  killChainPhases?: { phase: string; activity: string }[]
  strideSummary?: string
}

export type ExpertAssessment = {
  methodology: string
  assumptions: string[]
  blindSpots: string[]
  redTeamVerdict: string
}

export type DefensePriority = {
  rank: number
  action: string
  rationale: string
  effort: 'S' | 'M' | 'L'
}

export type ReconInsights = {
  authModel?: string
  trustBoundaries: string[]
  exposureZones: { zone: string; assets: string[]; risk: string }[]
  infrastructureSignals: string[]
  dataFlowNotes?: string
}

export type ScoreBreakdownItem = {
  category: string
  reason: string
  /** Weight 0–1 (e.g. 0.42 = 42% of final score) */
  weight: number
  /** Sub-score for this pillar, 0–100 */
  subScore: number
  /** Points added to final: weight × subScore */
  contribution: number
  /** @deprecated legacy delta format */
  delta?: number
}

export type ChatMessage = {
  role: 'user' | 'assistant'
  content: string
  at: string
}

export type SecurityIntelligence = {
  observedTechnologies: string[]
  commonRisks: string[]
  likelyMaturity: string
  securityPosture: string
}

export type SecurityDNA = {
  architecture: string
  exposure: string
  maturity: string
  attackSurface: string
  hardening: string
}

export type AttackerPerspective = {
  immediateObservations: string[]
  mostAttractiveTarget: string
  probableObjective: string
  probableRoute: string
  narrative: string
}

export type ExecutiveSummaryV2 = {
  overallPosture: string
  topRisk: string
  businessImpact: string
  priorityFix: string
  estimatedRiskReduction: string
  recommendedTimeline: string
}

export type AttackSurfaceMap = {
  root: string
  branches: { name: string; children: string[] }[]
}

export type FindingConsultant = {
  whatItMeans: string
  whyItMatters: string
  howAttackersAbuse: string
  realWorldExamples: string
  recommendedFix: string
  businessImpact: string
  implementationEffort: string
  riskReduction: string
  mitreMapping?: string
  detectionGuidance?: string
}

import type { PlatformIntelligence } from './platform/types'

export type { PlatformIntelligence } from './platform/types'

export type IntelligenceReport = {
  securityScore: number
  grade: string
  riskLevel: string
  technologies: string[]
  attackSurface: string[]
  attackSurfaceMap: AttackSurfaceMap
  vulnerabilities: Vulnerability[]
  attackPaths: AttackPathEdge[]
  simulatedPaths: SimulatedAttackPath[]
  recommendations: string[]
  nextSteps: string[]
  executiveSummary: string
  executiveV2: ExecutiveSummaryV2
  generatedAt: string
  /** @deprecated */
  digitalTwin: DigitalTwinGraph
  platform: PlatformIntelligence
  threatModel: ThreatModel
  scoreBreakdown: ScoreBreakdownItem[]
  intelligence: SecurityIntelligence
  securityDNA: SecurityDNA
  /** @deprecated */
  securityPersonality?: string
  attackerPerspective: AttackerPerspective
  expertAssessment?: ExpertAssessment
  defensePriorities?: DefensePriority[]
  reconInsights?: ReconInsights
  riskNarrative?: string
  targetUrl?: string
  targetTitle?: string
  /** Deterministic ETL payload for enterprise dashboard (zero AI in pipeline). */
  enterprise?: { scanResult: import('../backend/core/types').ScanResult }
}

/** @deprecated use IntelligenceReport */
export type ScanReport = IntelligenceReport

export type Challenge = {
  id: string
  user_id: string
  title: string
  description: string
  target_url?: string | null
  api_spec?: string | null
  status: 'pending' | 'running' | 'completed' | 'failed'
  created_at: string
}

export type Run = {
  id: string
  challenge_id: string
  user_id: string
  started_at: string
  finished_at?: string | null
  total_steps: number
  success?: boolean | null
  cost_tokens: number
  error_code?: string | null
  error_message?: string | null
}

export type AgentStep = {
  id: string
  run_id: string
  step: number
  agent_name: string
  input_json: Record<string, unknown>
  output_json: Record<string, unknown>
  reasoning?: string | null
  tokens: number
  duration_ms: number
  created_at?: string
}

export type HistoryEntry = {
  runId: string
  challengeId: string
  title: string
  targetUrl?: string
  finishedAt: string
  securityScore: number
  grade: string
  vulnerabilityCount: number
  technologies: string[]
}

export type HistoryComparison = {
  fixed: string[]
  introduced: string[]
  scoreDelta: number
  previousScore?: number
  currentScore: number
}
