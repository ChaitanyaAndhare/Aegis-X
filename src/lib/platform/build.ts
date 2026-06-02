import type { IntelligenceReport, ReconOutput, SimulatedAttackPath, Vulnerability } from '../types'
import { riskLevelFromScore, scoreToGrade } from '../aegis/scoring'
import { computeAttackabilityIndex, computeRadar } from '../aegis/attackability'
import {
  applyCoverageToScore,
  buildEvidenceDrivenGraph,
  buildScanSignals,
  buildUncertaintyLedger,
  computeAssessmentConfidence,
  computeEvidenceCoverage,
  computeFindingConfidence,
  defaultExecutivePosture,
  filterAttackPaths,
  pathsToRecords,
  sanitizeSecurityLanguage,
} from './evidence-engine'
import { sanitizeForDisplay } from './display-sanitize'
import type { StackFingerprint } from '../aegis/stack-fingerprint'
import type {
  BenchmarkResult,
  ConfidenceLevel,
  ControlDomain,
  ControlStatus,
  EvidenceFinding,
  ImpactLevel,
  ObservedSecurityPosture,
  PlatformIntelligence,
  TechnicalProfile,
} from './types'

function confidenceLevel(score: number): ConfidenceLevel {
  if (score >= 72) return 'High'
  if (score >= 45) return 'Medium'
  return 'Low'
}

export function enrichFinding(
  v: Vulnerability & {
    evidence?: string
    observedSignal?: string
    reasoning?: string
    potentialImpact?: string
    recommendedFix?: string
  },
  recon: ReconOutput,
  signals: ReturnType<typeof buildScanSignals>,
  coveragePercent: number,
  targetUrl?: string,
): EvidenceFinding {
  const signal =
    recon.findings.find((f) => v.title.toLowerCase().includes(f.signal.toLowerCase().slice(0, 8))) ??
    recon.findings[0]
  const observed = v.observedSignal ?? (signal ? `${signal.signal}: ${signal.detail.slice(0, 200)}` : targetUrl ? `GET ${targetUrl}` : 'Not directly observed')
  const evidence = v.evidence ?? signal?.detail ?? v.description.slice(0, 300)
  const facts = [observed, evidence].filter((x, i, a) => a.indexOf(x) === i)
  const inferences = [v.reasoning ?? v.description, v.potentialImpact].filter(Boolean) as string[]
  const confidenceScore = computeFindingConfidence(v, recon, signals, coveragePercent)

  return {
    id: v.id,
    title: v.title,
    severity: v.severity,
    confidenceScore,
    confidenceLevel: confidenceLevel(confidenceScore),
    facts,
    inferences,
    evidence,
    observedSignal: observed,
    reasoning: v.reasoning ?? v.description,
    potentialImpact: v.potentialImpact ?? v.businessCost ?? 'Impact depends on deployment context',
    recommendedFix: v.recommendedFix ?? v.remediation ?? 'Remediate per baseline for this control.',
    affectedAssets: recon.attackSurface.slice(0, 3),
    priority: v.priority ?? 5,
    cwe: v.cwe,
  }
}

function buildControlCoverage(recon: ReconOutput, signals: ReturnType<typeof buildScanSignals>): ControlDomain[] {
  const status = (good: boolean, partial: boolean): ControlStatus =>
    good ? 'Good' : partial ? 'Fair' : 'Poor'

  return [
    {
      domain: 'Authentication',
      status: status(signals.hasAuth, recon.attackSurface.some((s) => /login|auth/i.test(s))),
      reasoning: signals.hasAuth
        ? 'Login/session signals seen in surface or headers.'
        : 'No auth endpoints or cookies observed — not assessed.',
    },
    {
      domain: 'Authorization',
      status: 'Fair',
      reasoning: 'Authorization logic not testable without authenticated sessions.',
    },
    {
      domain: 'Transport Security',
      status: signals.usesHttpOnly
        ? 'Poor'
        : signals.usesHttps && signals.hstsPresent
          ? 'Good'
          : signals.usesHttps
            ? 'Fair'
            : 'Poor',
      reasoning: signals.usesHttpOnly
        ? 'HTTP only — cleartext transport observed.'
        : signals.usesHttps && signals.hstsPresent
          ? 'HTTPS and HSTS observed.'
          : signals.usesHttps
            ? 'HTTPS without confirmed HSTS.'
            : 'Transport not confirmed from URL/headers.',
    },
    {
      domain: 'Headers',
      status: status(signals.hasCsp && signals.hasSecurityHeaders, signals.hasSecurityHeaders || signals.hasCsp),
      reasoning: signals.hasCsp
        ? 'CSP present in headers.'
        : 'Protective headers weak or not observed.',
    },
    {
      domain: 'API Security',
      status: status(signals.hasApi && !recon.findings.some((f) => /api.*critical|api.*high/i.test(f.signal)), signals.hasApi),
      reasoning: signals.hasApi
        ? 'API routes in surface — authz not verified.'
        : 'No API surface identified externally.',
    },
    {
      domain: 'Dependencies',
      status: status(recon.technologies.length <= 4, recon.technologies.length > 6),
      reasoning: `${recon.technologies.length} technologies noted in recon.`,
    },
    {
      domain: 'Secrets',
      status: 'Fair',
      reasoning: 'Secrets not scanned in passive assessment.',
    },
    {
      domain: 'Monitoring',
      status: 'Fair',
      reasoning: 'Monitoring maturity not observable externally.',
    },
    {
      domain: 'Logging',
      status: 'Fair',
      reasoning: 'Logging controls not verified.',
    },
  ]
}

function controlCoveragePercent(domains: ControlDomain[]): number {
  const map = { Excellent: 100, Good: 80, Fair: 50, Poor: 20 }
  const sum = domains.reduce((s, d) => s + map[d.status], 0)
  return Math.round(sum / domains.length)
}

function buildSecurityDebt(recon: ReconOutput, findings: EvidenceFinding[], signals: ReturnType<typeof buildScanSignals>) {
  const headers = signals.usesHttpOnly ? 20 : !signals.hasCsp ? 12 : 4
  const transport = signals.usesHttpOnly ? 18 : !signals.hstsPresent && signals.usesHttps ? 8 : 0
  const dependencies = Math.min(20, recon.technologies.length * 2)
  const exposure = Math.min(20, recon.attackSurface.length * 1.5)
  const findingsDebt = Math.min(25, findings.filter((f) => f.severity === 'critical' || f.severity === 'high').length * 4)

  const contributors = [
    { category: 'Transport', score: Math.round(transport) },
    { category: 'Headers', score: Math.round(headers) },
    { category: 'Dependencies', score: Math.round(dependencies) },
    { category: 'Exposure', score: Math.round(exposure) },
    { category: 'Findings', score: Math.round(findingsDebt) },
  ]
    .filter((c) => c.score > 0)
    .sort((a, b) => b.score - a.score)

  const total = contributors.reduce((s, c) => s + c.score, 0)
  return {
    total,
    contributors,
    expectedReduction: Math.min(45, Math.round(total * 0.35)),
    topContributors: contributors.slice(0, 3),
  }
}

function inferMitre(f: EvidenceFinding) {
  const t = f.title.toLowerCase()
  if (/http(?!s)|cleartext|transport/i.test(t)) return { tactic: 'Collection', technique: 'Network Sniffing', techniqueId: 'T1040' }
  if (/csp|xss|script/i.test(t)) return { tactic: 'Execution', technique: 'Client-side script abuse', techniqueId: 'T1059' }
  if (/auth|session|cookie/i.test(t)) return { tactic: 'Credential Access', technique: 'Steal Web Session Cookie', techniqueId: 'T1539' }
  if (/api/i.test(t)) return { tactic: 'Initial Access', technique: 'Exploit Public-Facing Application', techniqueId: 'T1190' }
  if (/server|disclosure|version/i.test(t)) return { tactic: 'Discovery', technique: 'Software Discovery', techniqueId: 'T1518' }
  return { tactic: 'Discovery', technique: 'Reconnaissance', techniqueId: 'T1595' }
}

function buildObservedPosture(
  findings: EvidenceFinding[],
  signals: ReturnType<typeof buildScanSignals>,
  coverage: number,
): ObservedSecurityPosture {
  if (signals.usesHttpOnly) {
    return {
      label: 'Transport controls insufficient',
      summary: 'Transport encryption is not enforced at the application entry point.',
    }
  }
  if (findings.some((f) => f.severity === 'critical' || f.severity === 'high')) {
    return {
      label: 'Notable weaknesses (observed)',
      summary: 'One or more high-severity issues tied to recon evidence. Backend and auth remain unverified.',
    }
  }
  if (findings.length === 0 && coverage < 40) {
    return {
      label: 'Limited visibility',
      summary: 'Few external signals collected. Absence of findings does not imply strong security.',
    }
  }
  if (findings.length === 0) {
    return {
      label: 'No critical external findings',
      summary: 'No critical weaknesses seen in passive recon. Internal systems were not assessed.',
    }
  }
  return {
    label: 'Mixed observable posture',
    summary: 'Some externally visible gaps; severity weighted by evidence strength and coverage.',
  }
}

function buildArchitecture(
  recon: ReconOutput,
  title: string,
  findings: EvidenceFinding[],
  controls: ControlDomain[],
) {
  return {
    assets: [
      { name: title, type: 'Application', exposure: 'Internet-facing' },
      ...recon.attackSurface.slice(0, 6).map((s) => ({
        name: s,
        type: /api/i.test(s) ? 'API' : /auth|login/i.test(s) ? 'Auth' : 'Component',
        exposure: 'External',
      })),
    ],
    trustBoundaries: (recon.trustBoundaries?.length
      ? recon.trustBoundaries.map((t) => ({ name: t, description: 'From recon' }))
      : [
          { name: 'Internet', description: 'Untrusted clients' },
          { name: 'Application', description: 'Observed web tier only' },
        ]),
    entryPoints: recon.attackSurface.filter((s) => /login|api|upload|admin|auth/i.test(s)).slice(0, 8),
    threats: findings.slice(0, 6).map((f) => ({
      name: f.title,
      asset: f.affectedAssets[0] ?? title,
      severity: f.severity,
    })),
    controls: controls.map((c) => ({ name: c.domain, status: c.status })),
    missingControls: controls.filter((c) => c.status === 'Poor').map((c) => c.domain),
  }
}

function buildBenchmarking(score: number, techCount: number): BenchmarkResult[] {
  const segments: BenchmarkResult['segment'][] = ['Modern SaaS', 'Enterprise', 'Startup', 'Open Source']
  const baselines = [78, 82, 70, 65]
  return segments.map((segment, i) => {
    const baseline = baselines[i]!
    const percentile = Math.max(5, Math.min(92, Math.round((score / baseline) * 50 + 20 - techCount)))
    return {
      segment,
      percentile,
      relativeRisk: score >= baseline ? 'Below Average' : score >= baseline - 15 ? 'Average' : 'Above Average',
      maturity: score >= 85 ? 'Mature' : score >= 70 ? 'Developing' : 'Early',
    }
  })
}

function impactFromSeverity(sev: string): ImpactLevel {
  if (sev === 'critical' || sev === 'high') return 'High'
  if (sev === 'medium') return 'Medium'
  return 'Low'
}

function toTechnicalProfile(fp?: StackFingerprint): TechnicalProfile {
  return {
    frameworks: fp?.frameworks ?? [],
    authProviders: fp?.authProviders ?? [],
    hosting: fp?.hosting ?? [],
    exploitFocusAreas: fp?.exploitFocusAreas ?? [],
  }
}

export function buildPlatformIntelligence(
  report: IntelligenceReport,
  recon: ReconOutput,
  opts?: {
    scanDurationMs?: number
    githubInsights?: string[]
    headersSummary?: string
    pageSnippet?: string
    filteredPaths?: SimulatedAttackPath[]
    stackFingerprint?: StackFingerprint
  },
): PlatformIntelligence {
  const signals = buildScanSignals(recon, {
    targetUrl: report.targetUrl,
    headersSummary: opts?.headersSummary,
    pageSnippet: opts?.pageSnippet,
  })
  const coverage = computeEvidenceCoverage(recon, signals, (opts?.githubInsights?.length ?? 0) > 0)
  const findings = report.vulnerabilities.map((v) =>
    enrichFinding(v, recon, signals, coverage.percent, report.targetUrl),
  )
  const assessmentConfidence = computeAssessmentConfidence(recon, signals, coverage, findings.length)
  const uncertainty = buildUncertaintyLedger(recon, signals)
  const controls = buildControlCoverage(recon, signals)
  const debt = buildSecurityDebt(recon, findings, signals)
  const observedPosture = buildObservedPosture(findings, signals, coverage.percent)

  const paths = opts?.filteredPaths ?? report.simulatedPaths
  const attackPaths = pathsToRecords(paths, findings)
  const graph = buildEvidenceDrivenGraph(report.targetTitle ?? 'Target', findings, signals)

  const rawScore = report.securityScore
  const adjustedScore = applyCoverageToScore(rawScore, coverage.percent)

  const radar = computeRadar({
    recon,
    vulnerabilities: report.vulnerabilities,
    simulatedPaths: paths,
    securityScore: adjustedScore,
  })
  const { index, label } = computeAttackabilityIndex(radar, 100 - adjustedScore)

  const postureSummary = sanitizeForDisplay(
    sanitizeSecurityLanguage(defaultExecutivePosture(coverage.percent, assessmentConfidence.percent, findings.length)),
  )

  const remediation = (report.defensePriorities ?? []).slice(0, 8).map((d) => ({
    priority: d.rank,
    fix: d.action,
    effort: d.effort === 'S' ? 'Low' : d.effort === 'L' ? 'High' : 'Medium',
    riskReductionPercent: Math.max(5, Math.min(25, 20 - d.rank)),
  }))

  if (!remediation.length && findings[0]) {
    remediation.push({
      priority: 1,
      fix: findings[0].recommendedFix,
      effort: 'Medium',
      riskReductionPercent: 15,
    })
  }

  const topThreatsFromGraph = graph.nodes
    .filter((n) => n.type === 'Threat')
    .slice(0, 5)
    .map((n, i) => ({
      id: `tg${i}`,
      name: n.label,
      severity: 'medium',
      description: n.description,
    }))

  const displayPosture: ObservedSecurityPosture = {
    label: sanitizeForDisplay(observedPosture.label),
    summary: sanitizeForDisplay(observedPosture.summary),
  }

  return {
    riskScore: adjustedScore,
    rawRiskScore: rawScore,
    grade: report.grade,
    riskLevel: report.riskLevel,
    technicalProfile: toTechnicalProfile(opts?.stackFingerprint),
    evidenceCoverage: coverage,
    assessmentConfidence: {
      ...assessmentConfidence,
      reason: sanitizeForDisplay(assessmentConfidence.reason),
    },
    observedPosture: displayPosture,
    uncertainty,
    scanSignals: signals,
    attackabilityIndex: index,
    attackabilityLabel: label,
    securityDebt: debt,
    controlCoverage: controls,
    controlCoveragePercent: controlCoveragePercent(controls),
    securityPosture: postureSummary,
    architectureProfile: sanitizeForDisplay(
      sanitizeSecurityLanguage(report.securityDNA?.architecture ?? 'Externally observable web application'),
    ),
    findings,
    topFindings: [...findings].sort((a, b) => b.priority - a.priority).slice(0, 5),
    topThreats:
      topThreatsFromGraph.length > 0
        ? topThreatsFromGraph
        : report.threatModel.threats.slice(0, 5).map((t, i) => ({
            id: `t${i}`,
            name: t.name,
            severity: t.severity,
            description: sanitizeSecurityLanguage(t.description),
          })),
    topAttackPaths: attackPaths.slice(0, 5),
    threatExposureGraph: graph,
    attackPaths,
    architectureModel: buildArchitecture(recon, report.targetTitle ?? 'Target', findings, controls),
    mitreMapping: findings.slice(0, 12).map((f) => {
      const m = inferMitre(f)
      return { ...m, findingId: f.id, confidence: f.confidenceScore }
    }),
    businessImpacts: findings.map((f) => ({
      findingId: f.id,
      title: f.title,
      operational: impactFromSeverity(f.severity),
      financial: f.severity === 'critical' ? 'High' : f.severity === 'high' ? 'Medium' : 'Low',
      reputation: impactFromSeverity(f.severity),
      data: f.severity === 'critical' || f.severity === 'high' ? 'High' : 'Medium',
    })),
    remediationRoadmap: remediation,
    benchmarking: buildBenchmarking(adjustedScore, recon.technologies.length),
    scanDurationMs: opts?.scanDurationMs,
    githubInsights: opts?.githubInsights ?? [],
  }
}

export function applyPostureToReport(report: IntelligenceReport, platform: PlatformIntelligence): IntelligenceReport {
  const grade = scoreToGrade(platform.riskScore)
  const riskLevel = riskLevelFromScore(platform.riskScore)
  return {
    ...report,
    securityScore: platform.riskScore,
    grade,
    riskLevel,
    executiveV2: {
      ...report.executiveV2,
      overallPosture: platform.securityPosture,
    },
    intelligence: report.intelligence
      ? { ...report.intelligence, securityPosture: platform.observedPosture.summary }
      : report.intelligence,
    platform,
  }
}
