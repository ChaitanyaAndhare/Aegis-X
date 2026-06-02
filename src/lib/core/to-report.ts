import { buildDigitalTwin, buildAttackSurfaceMap } from '../aegis/digital-twin'
import { computeAttackabilityIndex, computeRadar } from '../aegis/attackability'
import type { IntelligenceReport, ReconOutput, SimulatedAttackPath, Vulnerability } from '../types'
import type { PlatformIntelligence, EvidenceFinding, ControlDomain } from '../platform/types'
import type { CoreAssessment } from './types'

function confidenceLevel(score: number): 'High' | 'Medium' | 'Low' {
  if (score >= 72) return 'High'
  if (score >= 45) return 'Medium'
  return 'Low'
}

function toVulnerabilities(core: CoreAssessment): Vulnerability[] {
  return core.findings.map((f, i) => ({
    id: f.id,
    title: f.title,
    severity: f.severity,
    description: f.reasoning,
    confidence: f.confidence,
    remediation: f.recommendedFix,
    impact: f.severity === 'critical' ? 9 : f.severity === 'high' ? 7 : 5,
    likelihood: Math.round(f.confidence / 10),
    priority: i + 1,
    mitreTactics: [f.mitreTactic],
  }))
}

function toEvidenceFindings(core: CoreAssessment): EvidenceFinding[] {
  return core.findings.map((f, i) => ({
    id: f.id,
    title: f.title,
    severity: f.severity,
    confidenceScore: f.confidence,
    confidenceLevel: confidenceLevel(f.confidence),
    facts: [f.observedSignal, ...(f.testPayload ? [`Probe: ${f.testPayload}`] : [])],
    inferences: [f.potentialImpact],
    evidence: f.evidenceSummary,
    observedSignal: f.observedSignal,
    reasoning: f.reasoning,
    potentialImpact: f.potentialImpact,
    recommendedFix: f.recommendedFix,
    affectedAssets: core.discovery.assets.slice(0, 3).map((a) => a.path),
    priority: i + 1,
    verificationStatus: f.verificationStatus,
    reproductionSteps: f.reproduction,
    testPayload: f.testPayload,
    checkId: f.checkId,
    category: f.category,
  }))
}

function toRecon(core: CoreAssessment): ReconOutput {
  return {
    technologies: core.discovery.technologies,
    attackSurface: core.discovery.probes
      .filter((p) => p.status > 0)
      .map((p) => `${p.path} (${p.note})`),
    findings: core.findings.map((f) => ({
      signal: f.title,
      detail: f.evidenceSummary,
      severity: f.severity,
      category: 'rule',
    })),
    authModel: core.discovery.authSignals.join(', ') || undefined,
    infrastructureSignals: core.discovery.technologies.filter((t) =>
      /cloudflare|vercel|nginx|apache/i.test(t),
    ),
  }
}

export function coreToIntelligenceReport(core: CoreAssessment): IntelligenceReport {
  const vulnerabilities = toVulnerabilities(core)
  const findings = toEvidenceFindings(core)
  const recon = toRecon(core)
  const topFinding = findings[0]

  const controlCoverage: ControlDomain[] = core.controls.map((c) => ({
    domain: c.domain,
    status: c.status === 'Good' ? 'Good' : c.status === 'Fair' ? 'Fair' : 'Poor',
    reasoning: c.reasoning,
  }))

  const simulatedPaths: SimulatedAttackPath[] = core.attackPaths.map((p, i) => ({
    id: p.id,
    name: p.name,
    steps: p.steps,
    likelihood: Math.round(p.confidence / 10),
    impact: 6,
    difficulty: 5,
    rank: i + 1,
  }))

  const radar = computeRadar({
    recon,
    vulnerabilities,
    simulatedPaths,
    securityScore: core.riskScore,
  })
  const attackability = computeAttackabilityIndex(radar, core.riskScore)

  const headerText = Object.entries(core.discovery.headers)
    .map(([k, v]) => `${k}: ${v}`)
    .join('\n')
  const scanSignals = {
    targetUrl: core.targetUrl,
    usesHttps: !core.discovery.cleartext,
    usesHttpOnly: core.discovery.cleartext,
    hstsPresent: core.discovery.hsts,
    hasCookies: core.discovery.hasCookies,
    hasAuth: core.discovery.hasAuth,
    hasForms: core.discovery.forms.length > 0,
    hasApi: core.discovery.hasApi,
    hasClientJs: core.discovery.hasClientJs,
    hasCsp: Boolean(core.discovery.headers['content-security-policy']),
    hasSecurityHeaders:
      Boolean(core.discovery.headers['x-frame-options']) ||
      Boolean(core.discovery.headers['x-content-type-options']),
    serverDisclosed: core.discovery.serverDisclosed,
    technologies: core.discovery.technologies,
    headerText,
    pageText: '',
  }

  const platform: PlatformIntelligence = {
    technicalProfile: {
      frameworks: core.discovery.technologies.filter((t) =>
        /react|next|vue|angular|svelte|wordpress/i.test(t),
      ),
      authProviders: core.discovery.technologies.filter((t) => /oauth|auth|clerk|okta/i.test(t)),
      hosting: core.discovery.technologies.filter((t) =>
        /cloudflare|vercel|nginx|apache|aws|azure/i.test(t),
      ),
      exploitFocusAreas: [],
    },
    riskScore: core.riskScore,
    grade: core.grade,
    riskLevel: core.riskLevel,
    evidenceCoverage: {
      percent: core.coveragePercent,
      areas: [
        { id: 'headers', label: 'Headers', assessed: true },
        { id: 'tls', label: 'TLS', assessed: true },
        { id: 'assets', label: 'Assets', assessed: true },
        { id: 'cookies', label: 'Cookies', assessed: core.discovery.hasCookies },
        { id: 'auth', label: 'Authentication', assessed: core.discovery.hasAuth },
        { id: 'backend', label: 'Backend', assessed: false },
        { id: 'infra', label: 'Infrastructure', assessed: false },
      ],
    },
    assessmentConfidence: {
      percent: core.confidencePercent,
      reason: 'Based on observable HTTP/TLS/header/cookie evidence (deterministic pipeline).',
    },
    observedPosture: core.observedPosture,
    uncertainty: [
      { level: 'Unknown', statement: 'Backend authorization and business logic not assessed.' },
      { level: 'Unknown', statement: 'Authenticated session flows not exercised.' },
    ],
    scanSignals,
    attackabilityIndex: attackability.index,
    attackabilityLabel: attackability.label,
    securityDebt: {
      total: core.securityDebt,
      contributors: core.findings.map((f) => ({ category: f.title, score: f.confidence / 5 })),
      expectedReduction: Math.min(40, core.remediation.length * 8),
      topContributors: core.findings.slice(0, 3).map((f) => ({ category: f.title, score: f.confidence / 5 })),
    },
    controlCoverage,
    controlCoveragePercent: Math.round(
      (controlCoverage.filter((c) => c.status === 'Good').length / controlCoverage.length) * 100,
    ),
    securityPosture: core.observedPosture.label,
    architectureProfile: core.discovery.technologies.slice(0, 5).join(', ') || 'Not identified',
    findings,
    topFindings: findings.slice(0, 5),
    topThreats: core.graph.nodes
      .filter((n) => n.type === 'Threat')
      .slice(0, 5)
      .map((n) => ({ id: n.id, name: n.label, severity: 'medium', description: n.description })),
    topAttackPaths: simulatedPaths.map((p) => ({
      id: p.id,
      name: p.name,
      steps: p.steps,
      likelihood: p.likelihood,
      impact: p.impact,
      complexity: p.difficulty,
      confidence: p.likelihood * 10,
      businessRisk: 'Context-dependent',
      evidenceNote: 'Rule-backed path',
    })),
    attackPaths: simulatedPaths.map((p) => ({
      id: p.id,
      name: p.name,
      steps: p.steps,
      likelihood: p.likelihood,
      impact: p.impact,
      complexity: p.difficulty,
      confidence: p.likelihood * 10,
      businessRisk: 'Context-dependent',
    })),
    threatExposureGraph: {
      nodes: core.graph.nodes.map((n) => ({
        id: n.id,
        label: n.label,
        type: n.type,
        description: n.description,
        evidence: n.evidence,
        relatedFindings: n.relatedFindings,
      })),
      edges: core.graph.edges.map((e) => ({
        id: e.id,
        source: e.source,
        target: e.target,
        relation: e.relation,
        evidence: e.evidence,
        reasoning: e.reasoning,
        confidence: e.confidence,
      })),
    },
    architectureModel: {
      assets: core.discovery.assets.slice(0, 8).map((a) => ({
        name: a.path,
        type: a.kind,
        exposure: 'external',
      })),
      trustBoundaries: [{ name: 'Internet → Origin', description: 'Public HTTP surface' }],
      entryPoints: [core.targetUrl],
      threats: core.graph.nodes
        .filter((n) => n.type === 'Threat')
        .map((n) => ({ name: n.label, asset: core.targetUrl, severity: 'medium' })),
      controls: controlCoverage.map((c) => ({ name: c.domain, status: c.status })),
      missingControls: core.findings.map((f) => f.title),
    },
    mitreMapping: core.findings.map((f) => ({
      tactic: f.mitreTactic,
      technique: f.mitreTechnique,
      findingId: f.id,
      confidence: f.confidence,
    })),
    businessImpacts: core.findings.slice(0, 5).map((f) => ({
      findingId: f.id,
      title: f.title,
      operational: 'Medium' as const,
      financial: 'Low' as const,
      reputation: f.severity === 'high' ? ('Medium' as const) : ('Low' as const),
      data: f.severity === 'high' ? ('Medium' as const) : ('Low' as const),
    })),
    remediationRoadmap: core.remediation.map((r) => ({
      priority: r.priority,
      fix: r.fix,
      effort: r.effort,
      riskReductionPercent: r.riskReductionPercent,
    })),
    benchmarking: [
      {
        segment: 'Modern SaaS',
        percentile: core.riskScore,
        relativeRisk: core.riskScore >= 70 ? 'Below Average' : 'Above Average',
        maturity: core.observedPosture.label,
      },
    ],
    scanDurationMs: core.durationMs,
    githubInsights: [],
  }

  const threatModel = {
    threats: platform.topThreats.map((t) => ({
      name: t.name,
      description: t.description,
      severity: t.severity,
    })),
    attackChains: [],
    businessImpact: core.findings.slice(0, 3).map((f) => f.potentialImpact),
    confidence: core.confidencePercent,
    mostLikely: { name: 'N/A', description: '', chain: [], confidence: 0 },
    mostDangerous: { name: 'N/A', description: '', chain: [], confidence: 0 },
    mostRealistic: { name: 'N/A', description: '', chain: [], confidence: 0 },
  }

  return {
    securityScore: core.riskScore,
    grade: core.grade,
    riskLevel: core.riskLevel,
    technologies: recon.technologies,
    attackSurface: recon.attackSurface,
    attackSurfaceMap: buildAttackSurfaceMap(recon, core.targetTitle),
    vulnerabilities,
    attackPaths: [],
    simulatedPaths,
    recommendations: core.remediation.map((r) => r.fix),
    nextSteps: core.remediation.slice(0, 3).map((r) => `[P${r.priority}] ${r.fix}`),
    executiveSummary: core.observedPosture.summary,
    executiveV2: {
      overallPosture: core.observedPosture.label,
      topRisk: topFinding?.title ?? 'No rule-matched gaps in scope',
      businessImpact: topFinding?.potentialImpact ?? 'Limited external visibility',
      priorityFix: topFinding?.recommendedFix ?? 'Maintain controls; expand assessment scope',
      estimatedRiskReduction: `${platform.securityDebt.expectedReduction}% potential from roadmap`,
      recommendedTimeline: 'Address high-severity header/transport items first',
    },
    generatedAt: core.scannedAt,
    digitalTwin: buildDigitalTwin({
      targetUrl: core.targetUrl,
      title: core.targetTitle,
      recon,
      vulnerabilities,
      threatModel,
    }),
    platform,
    threatModel,
    scoreBreakdown: [
      {
        category: 'Deterministic rules',
        reason: `${core.findings.length} findings from knowledge rules`,
        weight: 1,
        subScore: core.riskScore,
        contribution: core.riskScore,
      },
    ],
    intelligence: {
      observedTechnologies: recon.technologies,
      commonRisks: core.findings.map((f) => f.title),
      likelyMaturity: core.observedPosture.label,
      securityPosture: core.observedPosture.summary,
    },
    securityDNA: {
      architecture: recon.technologies[0] ?? 'Unknown',
      exposure: `${recon.attackSurface.length} external signals`,
      maturity: core.observedPosture.label,
      attackSurface: recon.attackSurface.slice(0, 3).join('; ') || 'Entry page',
      hardening: core.controls.filter((c) => c.status === 'Good').map((c) => c.domain).join(', ') || 'Limited',
    },
    attackerPerspective: {
      immediateObservations: core.findings.slice(0, 3).map((f) => f.observedSignal),
      mostAttractiveTarget: recon.attackSurface[0] ?? core.targetUrl,
      probableObjective: 'Reconnaissance and control gap exploitation',
      probableRoute: core.attackPaths[0]?.name ?? 'Passive observation only',
      narrative: core.observedPosture.summary,
    },
    expertAssessment: {
      methodology: core.pentest.methodology,
      assumptions: [core.pentest.scopeNote, `${core.pentest.requestCount} HTTP probes (rate-limited, non-destructive)`],
      blindSpots: ['Authenticated flows', 'Business logic abuse', 'Internal network', 'Denial-of-service not tested'],
      redTeamVerdict:
        'Automated middle-tier external pentest — educational payloads only. Manual validation and full engagement testing still recommended.',
    },
    defensePriorities: core.remediation.slice(0, 5).map((r) => ({
      rank: r.priority,
      action: r.fix,
      rationale: 'Rule-backed remediation from knowledge base',
      effort: r.effort === 'Low' ? 'S' : r.effort === 'High' ? 'L' : 'M',
    })),
    reconInsights: {
      authModel: recon.authModel,
      trustBoundaries: [{ zone: 'Public web', assets: [core.targetUrl], risk: 'external' }],
      exposureZones: [],
      infrastructureSignals: recon.infrastructureSignals ?? [],
    },
    targetUrl: core.targetUrl,
    targetTitle: core.targetTitle,
  }
}
