import type { Severity } from '../types'

export type EvidenceFact = {
  id: string
  type: 'header' | 'cookie' | 'technology' | 'asset' | 'tls' | 'http' | 'form' | 'auth'
  name: string
  value: string | null
  source: string
  observedAt: string
}

export type DiscoveryResult = {
  targetUrl: string
  finalUrl: string
  pageHtml: string
  statusCode: number
  headers: Record<string, string>
  cookies: { name: string; secure: boolean; httpOnly: boolean; sameSite: string | null }[]
  technologies: string[]
  assets: { kind: 'page' | 'script' | 'stylesheet' | 'route'; path: string }[]
  forms: { action: string; hasPassword: boolean }[]
  authSignals: string[]
  probes: { path: string; status: number; note: string }[]
  cleartext: boolean
  hsts: boolean
  hasClientJs: boolean
  hasApi: boolean
  hasAuth: boolean
  hasCookies: boolean
  serverDisclosed: boolean
}

export type RuleFinding = {
  id: string
  ruleId: string
  weaknessId: string
  title: string
  severity: Severity
  confidence: number
  evidenceIds: string[]
  evidenceSummary: string
  observedSignal: string
  reasoning: string
  potentialImpact: string
  recommendedFix: string
  mitreTactic: string
  mitreTechnique: string
  /** Active pentest verification when from pentest engine */
  verificationStatus?: 'verified' | 'potential' | 'observed'
  reproduction?: string[]
  testPayload?: string
  checkId?: string
  category?: string
}

export type CoreAssessment = {
  scanId: string
  targetUrl: string
  targetTitle: string
  scannedAt: string
  durationMs: number
  /** Full pentest engagement output (see `src/lib/pentest/types.ts`) */
  pentest: import('../pentest/types').PentestEngagement
  facts: EvidenceFact[]
  discovery: DiscoveryResult
  findings: RuleFinding[]
  graph: {
    nodes: { id: string; label: string; type: 'Asset' | 'Weakness' | 'Threat' | 'Control' | 'Impact'; description: string; evidence?: string; relatedFindings?: string[] }[]
    edges: { id: string; source: string; target: string; relation: 'EXPOSES' | 'ENABLES' | 'IMPACTS' | 'MITIGATED_BY'; evidence?: string; reasoning?: string; confidence?: number }[]
  }
  riskScore: number
  grade: string
  riskLevel: string
  securityDebt: number
  coveragePercent: number
  confidencePercent: number
  observedPosture: { label: string; summary: string }
  attackPaths: { id: string; name: string; steps: string[]; confidence: number }[]
  remediation: { priority: number; fix: string; effort: 'Low' | 'Medium' | 'High'; riskReductionPercent: number }[]
  controls: { domain: string; status: 'Good' | 'Fair' | 'Poor'; reasoning: string }[]
  assetsInventory: DiscoveryResult['assets']
}
