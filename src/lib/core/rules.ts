import type { Severity } from '../types'
import { uuid } from '../store'
import headerRules from '../../../knowledge/rules/headers.json'
import transportRules from '../../../knowledge/rules/transport.json'
import cookieRules from '../../../knowledge/rules/cookies.json'
import surfaceRules from '../../../knowledge/rules/surface.json'
import weaknessesKb from '../../../knowledge/kb/weaknesses.json'
import type { DiscoveryResult, EvidenceFact, RuleFinding } from './types'

type RuleWhen = {
  headerAbsent?: string
  requiresEncryptedTransport?: boolean
  cspFrameAncestorsAbsent?: boolean
  serverHeaderDisclosed?: boolean
  cleartextEntryPoint?: boolean
  cookieMissingFlag?: 'secure' | 'httponly'
  probeMatches?: string
}

type RuleDef = {
  id: string
  weaknessId: string
  when: RuleWhen
  confidence: number
}

type WeaknessKb = {
  title: string
  defaultSeverity: Severity
  mitre: { tactic: string; technique: string }
  remediation: string
  threats: {
    id: string
    label: string
    requiresClientJs?: boolean
    requiresCookies?: boolean
    requiresApi?: boolean
    requiresAuth?: boolean
  }[]
}

const ALL_RULES: RuleDef[] = [
  ...(headerRules as RuleDef[]),
  ...(transportRules as RuleDef[]),
  ...(cookieRules as RuleDef[]),
  ...(surfaceRules as RuleDef[]),
]

const KB = weaknessesKb as Record<string, WeaknessKb>

function headerAbsent(discovery: DiscoveryResult, name: string): boolean {
  const key = name.toLowerCase()
  if (discovery.headers[key]) return false
  if (key === 'content-security-policy' && discovery.headers['content-security-policy-report-only']) return false
  if (key === 'x-frame-options') {
    const csp = discovery.headers['content-security-policy'] ?? ''
    if (/frame-ancestors/i.test(csp)) return false
  }
  return true
}

function matchWhen(when: RuleWhen, discovery: DiscoveryResult): { matched: boolean; evidenceIds: string[]; summary: string } {
  const evidenceIds: string[] = []

  if (when.headerAbsent) {
    if (when.requiresEncryptedTransport && discovery.cleartext) {
      return { matched: false, evidenceIds, summary: '' }
    }
    if (!headerAbsent(discovery, when.headerAbsent)) {
      return { matched: false, evidenceIds, summary: '' }
    }
    return {
      matched: true,
      evidenceIds,
      summary: `Response header "${when.headerAbsent}" not observed on ${discovery.finalUrl}`,
    }
  }

  if (when.cleartextEntryPoint && discovery.cleartext) {
    return {
      matched: true,
      evidenceIds,
      summary: `Entry URL uses cleartext HTTP (${discovery.targetUrl})`,
    }
  }

  if (when.serverHeaderDisclosed && discovery.serverDisclosed) {
    const server = discovery.headers.server ?? discovery.headers['x-powered-by'] ?? 'disclosed'
    return { matched: true, evidenceIds, summary: `Server technology disclosed: ${server}` }
  }

  if (when.cookieMissingFlag && discovery.cookies.length) {
    const bad = discovery.cookies.filter((c) =>
      when.cookieMissingFlag === 'secure' ? !c.secure : !c.httpOnly,
    )
    if (!bad.length) return { matched: false, evidenceIds, summary: '' }
    return {
      matched: true,
      evidenceIds,
      summary: `Cookie(s) missing ${when.cookieMissingFlag}: ${bad.map((c) => c.name).join(', ')}`,
    }
  }

  if (when.probeMatches) {
    const hit = discovery.probes.find(
      (p) => p.path.includes(when.probeMatches!) && p.status > 0 && p.status < 500,
    )
    if (!hit) return { matched: false, evidenceIds, summary: '' }
    return {
      matched: true,
      evidenceIds,
      summary: `Probe ${hit.path} returned HTTP ${hit.status} (${hit.note})`,
    }
  }

  return { matched: false, evidenceIds, summary: '' }
}

export function evaluateRules(
  discovery: DiscoveryResult,
  facts: EvidenceFact[],
): RuleFinding[] {
  const findings: RuleFinding[] = []

  for (const rule of ALL_RULES) {
    const { matched, summary } = matchWhen(rule.when, discovery)
    if (!matched) continue

    const kb = KB[rule.weaknessId]
    if (!kb) continue

    const linkedFacts = facts
      .filter((f) => summary.toLowerCase().includes(f.name.toLowerCase()) || f.type === 'header' || f.type === 'cookie')
      .slice(0, 3)
      .map((f) => f.id)

    const threat = kb.threats[0]
    findings.push({
      id: uuid(),
      ruleId: rule.id,
      weaknessId: rule.weaknessId,
      title: kb.title,
      severity: kb.defaultSeverity,
      confidence: rule.confidence,
      evidenceIds: linkedFacts,
      evidenceSummary: summary,
      observedSignal: summary,
      reasoning: `Rule ${rule.id} matched observable conditions (deterministic).`,
      potentialImpact: threat?.label ?? 'Exposure depends on deployment context',
      recommendedFix: kb.remediation,
      mitreTactic: kb.mitre.tactic,
      mitreTechnique: kb.mitre.technique,
    })
  }

  const order: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }
  return findings.sort((a, b) => order[a.severity] - order[b.severity])
}
