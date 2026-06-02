import type { ReconOutput, SimulatedAttackPath, Vulnerability } from '../types'
import type {
  AssessmentConfidence,
  AttackPathRecord,
  EvidenceCoverage,
  EvidenceFinding,
  ThreatExposureEdge,
  ThreatExposureNode,
  UncertaintyItem,
} from './types'

export type ScanSignals = {
  targetUrl?: string
  usesHttps: boolean
  usesHttpOnly: boolean
  hstsPresent: boolean
  hasCookies: boolean
  hasAuth: boolean
  hasForms: boolean
  hasApi: boolean
  hasClientJs: boolean
  hasCsp: boolean
  hasSecurityHeaders: boolean
  serverDisclosed: boolean
  technologies: string[]
  headerText: string
  pageText: string
}

const FORBIDDEN_PHRASES = [
  /\bwebsite is secure\b/i,
  /\bvery secure\b/i,
  /\bthis (site|website|application) is safe\b/i,
  /\bno significant security concerns\b/i,
  /\bappears secure\b/i,
  /\bwell protected\b/i,
  /\bfully protected\b/i,
]

const AUTH_PATH_STEPS =
  /session\s*theft|account\s*takeover|credential\s*theft|cookie\s*hijack|session\s*hijack|steal\s*session/i
const FORM_PATH_STEPS = /credential\s*theft|password\s*spray|brute\s*force\s*login/i
const API_PATH_STEPS = /api\s*abuse|broken\s*object|bola|bfla|mass\s*assignment/i
const COOKIE_PATH_STEPS = /cookie\s*hijack|session\s*fixation/i
const CSRF_PATH_STEPS = /\bcsrf\b|cross.?site\s*request/i
const XSS_TAKEOVER = /xss.*account|session\s*theft.*xss/i

export function sanitizeSecurityLanguage(text: string): string {
  let out = text
  for (const re of FORBIDDEN_PHRASES) {
    out = out.replace(re, 'observable posture is limited to external signals; deeper testing not performed')
  }
  return out
}

export function buildScanSignals(
  recon: ReconOutput,
  opts?: { targetUrl?: string; headersSummary?: string; pageSnippet?: string },
): ScanSignals {
  const headerText = opts?.headersSummary ?? ''
  const pageText = opts?.pageSnippet ?? ''
  const blob = [
    headerText,
    pageText,
    ...recon.findings.map((f) => `${f.signal} ${f.detail}`),
    ...recon.attackSurface,
    recon.authModel ?? '',
    ...recon.technologies,
  ].join('\n').toLowerCase()

  let usesHttps = false
  let usesHttpOnly = false
  if (opts?.targetUrl) {
    try {
      const u = new URL(opts.targetUrl)
      usesHttps = u.protocol === 'https:'
      usesHttpOnly = u.protocol === 'http:'
    } catch {
      /* ignore */
    }
  }
  if (/https:\/\//i.test(blob) || /status:\s*200/i.test(headerText) && /https/i.test(headerText)) {
    usesHttps = usesHttps || /https/i.test(blob)
  }
  if (/http:\/\//i.test(opts?.targetUrl ?? '') || usesHttpOnly) usesHttpOnly = true
  if (headerText.toLowerCase().includes('http://') && !usesHttps) usesHttpOnly = true

  const hstsPresent = /strict-transport-security|hsts/i.test(blob)
  const hasCookies = /set-cookie|cookie:/i.test(blob) || /session|auth.*cookie/i.test(blob)
  const hasAuth =
    /login|sign[\s-]?in|oauth|bearer|jwt|session|authenticate|auth\//i.test(blob) ||
    recon.attackSurface.some((s) => /login|auth|signin|oauth/i.test(s))
  const hasForms = /<form|type=["']password|login form|sign[\s-]?in/i.test(blob)
  const hasApi =
    recon.attackSurface.some((s) => /api|graphql|rest|grpc|webhook/i.test(s)) ||
    /\/api\/|graphql|swagger|openapi/i.test(blob)
  const hasClientJs =
    recon.technologies.some((t) => /react|vue|angular|next|nuxt|svelte|javascript|webpack|bundle/i.test(t)) ||
    /<script|\.js["']/i.test(pageText)
  const hasCsp = /content-security-policy|csp/i.test(blob)
  const hasSecurityHeaders =
    hasCsp || /x-frame-options|x-content-type-options|referrer-policy|permissions-policy/i.test(blob)
  const serverDisclosed = /server:\s*[^\n]+/i.test(headerText) && !/server:\s*unknown/i.test(headerText)

  return {
    targetUrl: opts?.targetUrl,
    usesHttps,
    usesHttpOnly,
    hstsPresent,
    hasCookies,
    hasAuth,
    hasForms,
    hasApi,
    hasClientJs,
    hasCsp,
    hasSecurityHeaders,
    serverDisclosed,
    technologies: recon.technologies,
    headerText,
    pageText,
  }
}

/** Inject deterministic transport findings so HTTP cannot score above HTTPS by accident. */
export function injectTransportFindings(recon: ReconOutput, signals: ScanSignals): ReconOutput {
  const findings = [...recon.findings]
  const hasTransportFinding = findings.some((f) => /transport|tls|https|hsts|cleartext/i.test(f.signal))

  if (signals.usesHttpOnly && !signals.usesHttps) {
    findings.unshift({
      signal: 'Transport encryption not enforced',
      detail: 'Application entry point does not enforce encryption in transit. Session and credential data may be exposed to network observers.',
      severity: 'high',
      category: 'transport',
    })
  } else if (signals.usesHttps && !signals.hstsPresent) {
    findings.push({
      signal: 'Transport hardening incomplete',
      detail: 'Encryption in transit is in use but strict transport enforcement was not observed in response headers.',
      severity: 'medium',
      category: 'transport',
    })
  } else if (signals.usesHttps && signals.hstsPresent && !hasTransportFinding) {
    findings.push({
      signal: 'Transport hardening observed',
      detail: 'Encryption in transit and strict transport enforcement signals observed in response headers.',
      severity: 'info',
      category: 'transport',
    })
  }

  return { ...recon, findings }
}

export function computeEvidenceCoverage(
  recon: ReconOutput,
  signals: ScanSignals,
  githubAssessed: boolean,
): EvidenceCoverage {
  const areas = [
    { id: 'headers', label: 'Headers', assessed: Boolean(signals.headerText.trim()), note: 'HTTP response headers' },
    { id: 'tls', label: 'TLS / Transport', assessed: signals.usesHttps || signals.usesHttpOnly, note: 'Protocol from URL + headers' },
    { id: 'public', label: 'Public assets', assessed: recon.attackSurface.length > 0 || Boolean(signals.pageText), note: 'Page + surface entries' },
    { id: 'backend', label: 'Backend logic', assessed: false, note: 'Not assessed externally' },
    { id: 'authz', label: 'Authorization', assessed: false, note: 'No authenticated testing' },
    { id: 'cloud', label: 'Cloud configuration', assessed: false, note: 'Not in scope' },
    { id: 'source', label: 'Source code', assessed: githubAssessed, note: githubAssessed ? 'GitHub signals only' : 'Not provided' },
    { id: 'internal_api', label: 'Internal APIs', assessed: false, note: 'Not reachable' },
  ]
  const assessedCount = areas.filter((a) => a.assessed).length
  const percent = Math.round((assessedCount / areas.length) * 100)
  return { percent, areas }
}

export function computeAssessmentConfidence(
  recon: ReconOutput,
  signals: ScanSignals,
  coverage: EvidenceCoverage,
  findingCount: number,
): AssessmentConfidence {
  let score = 15
  if (signals.headerText.trim()) score += 18
  if (signals.pageText.trim()) score += 12
  if (recon.technologies.length) score += 8
  if (recon.findings.length >= 3) score += 10
  if (findingCount > 0) score += 8
  if (signals.usesHttps || signals.usesHttpOnly) score += 5
  score += Math.round(coverage.percent * 0.25)

  const percent = Math.max(12, Math.min(85, score))
  const reason =
    percent < 40
      ? 'Assessment based primarily on limited public HTTP responses. Backend, authorization, and infrastructure were not tested.'
      : percent < 65
        ? 'Moderate visibility: public headers, page content, and surface mapping. No authenticated or internal testing.'
        : 'Reasonable external visibility, but backend authorization and cloud configuration remain unverified.'

  return { percent, reason }
}

export function buildUncertaintyLedger(
  recon: ReconOutput,
  signals: ScanSignals,
): UncertaintyItem[] {
  const items: UncertaintyItem[] = []

  for (const t of recon.technologies.slice(0, 4)) {
    items.push({ level: 'Known', statement: `${t} referenced in recon` })
  }
  if (signals.serverDisclosed) {
    items.push({ level: 'Known', statement: 'Server / stack information disclosed in headers' })
  }
  if (signals.usesHttpOnly) {
    items.push({ level: 'Known', statement: 'Site served over cleartext HTTP' })
  }
  if (signals.usesHttps) {
    items.push({ level: 'Known', statement: 'HTTPS used for transport' })
  }
  if (signals.hasClientJs) {
    items.push({ level: 'Likely', statement: 'Client-side application logic present' })
  }
  if (!signals.hasCsp && signals.hasClientJs) {
    items.push({ level: 'Possible', statement: 'Client-side injection exposure if user-controlled input reaches DOM' })
  }
  if (!signals.hasAuth) {
    items.push({ level: 'Unknown', statement: 'Authentication and session management model' })
  } else {
    items.push({ level: 'Likely', statement: 'Authentication or session mechanisms indicated' })
  }
  items.push({ level: 'Unknown', statement: 'Backend authorization and business logic' })
  items.push({ level: 'Unknown', statement: 'Cloud / IAM configuration' })

  return items.slice(0, 12)
}

function pathStepBlocked(step: string, signals: ScanSignals): boolean {
  const s = step.toLowerCase()
  if (AUTH_PATH_STEPS.test(s) && !signals.hasAuth && !signals.hasCookies) return true
  if (FORM_PATH_STEPS.test(s) && !signals.hasForms && !signals.hasAuth) return true
  if (API_PATH_STEPS.test(s) && !signals.hasApi) return true
  if (COOKIE_PATH_STEPS.test(s) && !signals.hasCookies) return true
  if (CSRF_PATH_STEPS.test(s) && !signals.hasForms) return true
  if (XSS_TAKEOVER.test(s) && !signals.hasAuth) return true
  return false
}

export function filterAttackPaths(paths: SimulatedAttackPath[], signals: ScanSignals): SimulatedAttackPath[] {
  return paths.filter((p) => {
    if (p.steps.some((step) => pathStepBlocked(step, signals))) return false
    const joined = `${p.name} ${p.steps.join(' ')}`.toLowerCase()
    if (/session theft|account takeover|credential theft/.test(joined) && !signals.hasAuth && !signals.hasCookies) {
      return false
    }
    if (/api abuse|broken access/.test(joined) && !signals.hasApi) return false
    return p.steps.length >= 2
  })
}

export function deriveThreatChain(
  finding: EvidenceFinding,
  signals: ScanSignals,
  assetLabel: string,
): { weakness: string; threat: string; impact: string; reasoning: string } | null {
  const t = `${finding.title} ${finding.evidence}`.toLowerCase()

  if (/http(?!s)|cleartext|unencrypted transport/i.test(t) || (signals.usesHttpOnly && /transport|tls/i.test(t))) {
    return {
      weakness: 'Cleartext HTTP',
      threat: 'Traffic interception',
      impact: 'Credential or data exposure in transit',
      reasoning: 'HTTP does not encrypt traffic; observers on the network can read or modify requests.',
    }
  }
  if (/server:|version disclosure|powered.by|x-powered/i.test(t)) {
    return {
      weakness: 'Technology disclosure',
      threat: 'Reconnaissance',
      impact: 'Increased attack surface',
      reasoning: 'Disclosed stack versions help attackers select exploits.',
    }
  }
  if (/csp|content-security-policy/i.test(t)) {
    if (!signals.hasClientJs) {
      return {
        weakness: 'Missing CSP',
        threat: 'Reduced browser policy enforcement',
        impact: 'Defense-in-depth gap',
        reasoning: 'CSP absent; limited client-side script surface observed, so injection impact is uncertain.',
      }
    }
    return {
      weakness: 'Missing or weak CSP',
      threat: 'Client-side script injection',
      impact: 'Content manipulation or data exfiltration from browser',
      reasoning: 'Scripts run without strict CSP; only relevant where client-side code exists.',
    }
  }
  if (/x-frame|clickjack/i.test(t)) {
    return {
      weakness: 'Clickjacking protections missing',
      threat: 'UI redress',
      impact: 'User action abuse',
      reasoning: 'Page may be framed to trick users into unintended actions.',
    }
  }
  if (/hsts/i.test(t)) {
    return {
      weakness: 'HSTS not enforced',
      threat: 'Protocol downgrade',
      impact: 'Session or credential exposure',
      reasoning: 'Without HSTS, clients may be tricked onto HTTP.',
    }
  }
  if (/cookie|secure flag|samesite/i.test(t) && signals.hasCookies) {
    return {
      weakness: 'Cookie hardening gap',
      threat: 'Session token abuse',
      impact: 'Session compromise',
      reasoning: 'Cookies observed; misconfiguration may enable theft via XSS or network.',
    }
  }
  if (/cookie|session/i.test(t) && !signals.hasCookies) return null

  if (/xss|script|inject/i.test(t)) {
    if (!signals.hasClientJs) return null
    if (signals.hasAuth || signals.hasCookies) {
      return {
        weakness: finding.title,
        threat: 'Cross-site scripting',
        impact: signals.hasAuth ? 'Session or account abuse' : 'Client data exposure',
        reasoning: 'Client-side context with scripting; validate input sinks.',
      }
    }
    return {
      weakness: finding.title,
      threat: 'DOM or script abuse',
      impact: 'Information disclosure in browser',
      reasoning: 'Script context without confirmed auth; impact limited to client scope.',
    }
  }

  if (/api|graphql|endpoint/i.test(t) && signals.hasApi) {
    return {
      weakness: finding.title,
      threat: 'API misuse',
      impact: 'Unauthorized data access or abuse',
      reasoning: 'API surface observed; abuse depends on authz not visible externally.',
    }
  }
  if (/api/i.test(t) && !signals.hasApi) return null

  if (/auth|login|oauth/i.test(t) && signals.hasAuth) {
    return {
      weakness: finding.title,
      threat: 'Authentication abuse',
      impact: 'Unauthorized access',
      reasoning: 'Auth entry points observed; weaknesses need targeted testing.',
    }
  }
  if (/session|account takeover|credential/i.test(t) && !signals.hasAuth) return null

  if (/dependency|supply|npm|package/i.test(t)) {
    return {
      weakness: finding.title,
      threat: 'Supply chain risk',
      impact: 'Compromise via vulnerable component',
      reasoning: 'Third-party or dependency signals in recon.',
    }
  }

  return {
    weakness: finding.title,
    threat: 'Misconfiguration abuse',
    impact: finding.potentialImpact.slice(0, 120),
    reasoning: finding.reasoning,
  }
}

export function buildEvidenceDrivenGraph(
  assetLabel: string,
  findings: EvidenceFinding[],
  signals: ScanSignals,
): { nodes: ThreatExposureNode[]; edges: ThreatExposureEdge[] } {
  const nodes: ThreatExposureNode[] = []
  const edges: ThreatExposureEdge[] = []
  const rootId = 'asset:root'

  nodes.push({
    id: rootId,
    label: assetLabel,
    type: 'Asset',
    description: 'Primary externally observed application asset.',
    evidence: signals.targetUrl ? `Target: ${signals.targetUrl}` : undefined,
    affectedAssets: [assetLabel],
  })

  let chainIndex = 0
  for (const f of findings) {
    const chain = deriveThreatChain(f, signals, assetLabel)
    if (!chain) continue

    const wid = `weakness:${f.id}`
    const tid = `threat:${f.id}`
    const iid = `impact:${f.id}`

    nodes.push({
      id: wid,
      label: chain.weakness,
      type: 'Weakness',
      description: chain.reasoning,
      evidence: f.evidence,
      confidence: f.confidenceScore,
      relatedFindings: [f.id],
    })
    nodes.push({
      id: tid,
      label: chain.threat,
      type: 'Threat',
      description: chain.reasoning,
      evidence: f.observedSignal,
      confidence: f.confidenceScore,
      relatedFindings: [f.id],
    })
    nodes.push({
      id: iid,
      label: chain.impact,
      type: 'Impact',
      description: f.potentialImpact,
      evidence: f.evidence,
      confidence: f.confidenceScore,
      relatedFindings: [f.id],
    })

    const e1 = `e-${chainIndex}-expose`
    const e2 = `e-${chainIndex}-enable`
    const e3 = `e-${chainIndex}-impact`
    chainIndex++

    edges.push({
      id: e1,
      source: rootId,
      target: wid,
      relation: 'EXPOSES',
      evidence: f.observedSignal,
      reasoning: `Observed: ${f.title}. ${chain.reasoning}`,
      confidence: f.confidenceScore,
      impact: chain.weakness,
    })
    edges.push({
      id: e2,
      source: wid,
      target: tid,
      relation: 'ENABLES',
      evidence: f.evidence,
      reasoning: chain.reasoning,
      confidence: f.confidenceScore,
      impact: chain.threat,
    })
    edges.push({
      id: e3,
      source: tid,
      target: iid,
      relation: 'IMPACTS',
      evidence: f.evidence,
      reasoning: f.reasoning,
      confidence: f.confidenceScore,
      impact: chain.impact,
    })
  }

  if (signals.hasCsp) {
    const cid = 'control:csp'
    nodes.push({
      id: cid,
      label: 'CSP observed',
      type: 'Control',
      description: 'Content-Security-Policy signal in headers.',
      evidence: signals.headerText.slice(0, 200),
    })
    edges.push({
      id: 'e-csp',
      source: cid,
      target: rootId,
      relation: 'MITIGATED_BY',
      reasoning: 'Partial mitigation for script injection.',
      confidence: 70,
    })
  }

  return { nodes, edges }
}

export function pathsToRecords(paths: SimulatedAttackPath[], findings: EvidenceFinding[]): AttackPathRecord[] {
  if (!paths.length) {
    return [
      {
        id: 'none',
        name: 'No evidence-supported attack path identified',
        steps: ['Insufficient observable prerequisites for chained exploitation'],
        likelihood: 0,
        impact: 0,
        complexity: 0,
        confidence: 0,
        businessRisk: 'Not assessed',
        evidenceNote: 'Passive scan only; no chain met evidence rules.',
      },
    ]
  }

  return paths.slice(0, 5).map((p) => {
    const avgConf =
      findings.length > 0
        ? Math.round(findings.reduce((s, f) => s + f.confidenceScore, 0) / findings.length)
        : 40
    const pathConf = Math.max(15, Math.min(avgConf, 88))
    return {
      id: p.id,
      name: p.name,
      steps: p.steps,
      likelihood: p.likelihood,
      impact: p.impact,
      complexity: p.difficulty,
      confidence: pathConf,
      businessRisk: p.objective ?? 'Depends on observed surface',
      evidenceNote: p.steps.join(' → '),
    }
  })
}

export function applyCoverageToScore(rawScore: number, coveragePercent: number): number {
  const cap = 45 + Math.round(coveragePercent * 0.45)
  const pulled = rawScore * (0.55 + (coveragePercent / 100) * 0.45)
  return Math.round(Math.min(cap, Math.max(0, pulled)))
}

export function computeFindingConfidence(
  v: Vulnerability,
  recon: ReconOutput,
  signals: ScanSignals,
  coveragePercent: number,
): number {
  let score = Math.round((v.confidence ?? 0.5) * 100)
  const titleLower = v.title.toLowerCase()
  const matched = recon.findings.some(
    (f) =>
      titleLower.includes(f.signal.toLowerCase().slice(0, 10)) ||
      f.detail.toLowerCase().includes(titleLower.slice(0, 10)),
  )
  if (matched) score += 12
  else score -= 15
  if (v.evidence && v.evidence.length > 20) score += 8
  if (signals.headerText && /header|csp|cookie|tls|transport/i.test(v.title)) score += 5
  score = Math.round(score * (0.5 + coveragePercent / 200))
  return Math.max(12, Math.min(88, score))
}

export function defaultExecutivePosture(coverage: number, confidence: number, findingCount: number): string {
  if (findingCount === 0) {
    return `Based on publicly observable evidence (${coverage}% surface coverage), no critical weaknesses were identified in passive recon. Assessment confidence is ${confidence}% — backend systems, authorization, and infrastructure were not tested.`
  }
  return `Observed security posture reflects ${findingCount} evidence-backed finding(s) from external recon only (${coverage}% coverage). Assessment confidence is ${confidence}% — do not treat this as a full penetration test.`
}
