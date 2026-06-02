import { buildAttackSurfaceMap, buildDigitalTwin } from './aegis/digital-twin'
import { buildPlatformIntelligence } from './platform/build'
import { computeWeightedScore, scoreToGrade, riskLevelFromScore } from './aegis/scoring'
import type {
  AttackPathEdge,
  IntelligenceReport,
  ReconOutput,
  ThreatModel,
  Vulnerability,
} from './types'
import { isIntelligenceReport } from './normalize-report'

type LegacyReport = {
  securityScore: number
  grade: string
  riskLevel: string
  technologies: string[]
  attackSurface: string[]
  vulnerabilities: Array<{
    id?: string
    title: string
    severity: Vulnerability['severity']
    description: string
    confidence: number
    cwe?: string
    remediation?: string
  }>
  attackPaths: AttackPathEdge[]
  recommendations: string[]
  nextSteps: string[]
  executiveSummary: string
  generatedAt: string
  targetUrl?: string
  targetTitle?: string
}

export function upgradeLegacyReport(
  report: unknown,
  meta?: { targetUrl?: string; targetTitle?: string },
): IntelligenceReport | null {
  if (!report || typeof report !== 'object') return null
  if (isIntelligenceReport(report)) return report

  const leg = report as LegacyReport
  if (typeof leg.securityScore !== 'number' || !Array.isArray(leg.vulnerabilities)) return null

  const vulnerabilities: Vulnerability[] = leg.vulnerabilities.map((v, i) => ({
    id: v.id ?? `v${i + 1}`,
    title: v.title,
    severity: v.severity,
    description: v.description,
    confidence: v.confidence ?? 0.7,
    cwe: v.cwe,
    remediation: v.remediation,
    impact: v.severity === 'critical' ? 9 : v.severity === 'high' ? 7 : 5,
    likelihood: v.severity === 'critical' ? 8 : v.severity === 'high' ? 6 : 4,
    exploitability: 5,
    businessCost: v.severity === 'critical' ? 'High' : 'Medium',
    priority: v.severity === 'critical' ? 9 : v.severity === 'high' ? 7 : 5,
  }))

  const recon: ReconOutput = {
    technologies: leg.technologies ?? [],
    attackSurface: leg.attackSurface ?? [],
    findings: leg.attackSurface?.map((s) => ({ signal: s, detail: 'Observed attack surface component' })) ?? [],
  }

  const defaultChain = leg.attackPaths?.[0]
    ? leg.attackPaths.map((p) => p.source).concat(leg.attackPaths[leg.attackPaths.length - 1]?.target ?? '')
    : ['Entry point', 'Weak control', 'Impact']

  const threatModel: ThreatModel = {
    threats: vulnerabilities.slice(0, 5).map((v) => ({
      name: v.title,
      description: v.description.slice(0, 200),
      severity: v.severity,
    })),
    attackChains: [],
    businessImpact: ['Potential data exposure', 'Reputation impact', 'Operational disruption'],
    confidence: 0.75,
    mostLikely: {
      name: vulnerabilities[0]?.title ?? 'Likely attack chain',
      description: vulnerabilities[0]?.description ?? 'Derived from scan findings',
      chain: defaultChain.filter(Boolean),
      confidence: 0.7,
    },
    mostDangerous: {
      name: vulnerabilities.find((v) => v.severity === 'critical' || v.severity === 'high')?.title ?? 'High-impact chain',
      description: 'Highest severity finding chain',
      chain: defaultChain.filter(Boolean),
      confidence: 0.65,
    },
    mostRealistic: {
      name: 'Realistic attacker path',
      description: leg.executiveSummary?.slice(0, 150) ?? 'Based on observed surface',
      chain: defaultChain.filter(Boolean),
      confidence: 0.8,
    },
  }

  const title = meta?.targetTitle ?? 'Target'

  const simulatedPaths = (leg.attackPaths?.length
    ? [
        {
          id: 'p1',
          name: 'Primary attack path',
          steps: leg.attackPaths.map((p) => `${p.source} → ${p.target} (${p.label})`),
          likelihood: 7,
          impact: 8,
          difficulty: 5,
          rank: 1,
        },
      ]
    : [
        {
          id: 'p1',
          name: 'Inferred path',
          steps: defaultChain,
          likelihood: 6,
          impact: 7,
          difficulty: 5,
          rank: 1,
        },
      ])

  const { score, breakdown: scoreBreakdown } = computeWeightedScore({
    recon,
    vulnerabilities,
    simulatedPaths,
  })

  const base = {
    securityScore: score,
    grade: scoreToGrade(score),
    riskLevel: riskLevelFromScore(score),
    technologies: leg.technologies ?? [],
    attackSurface: leg.attackSurface ?? [],
    attackSurfaceMap: buildAttackSurfaceMap(recon, title),
    vulnerabilities,
    attackPaths: leg.attackPaths ?? [],
    simulatedPaths,
    recommendations: leg.recommendations ?? [],
    nextSteps: leg.nextSteps ?? [],
    executiveSummary: leg.executiveSummary ?? '',
    executiveV2: {
      overallPosture: leg.executiveSummary ?? `Security posture grade ${leg.grade}`,
      topRisk: vulnerabilities[0]?.title ?? 'Review findings',
      businessImpact: 'See vulnerability details for business impact assessment.',
      priorityFix: vulnerabilities[0]?.remediation ?? leg.recommendations?.[0] ?? 'Address top findings',
      estimatedRiskReduction: '15–30% with priority fixes',
      recommendedTimeline: '30–90 days phased remediation',
    },
    generatedAt: leg.generatedAt ?? new Date().toISOString(),
    digitalTwin: buildDigitalTwin({
      targetUrl: meta?.targetUrl,
      title,
      recon,
      vulnerabilities,
      threatModel,
    }),
    threatModel,
    scoreBreakdown,
    intelligence: {
      observedTechnologies: leg.technologies ?? [],
      commonRisks: vulnerabilities.slice(0, 4).map((v) => v.title),
      likelyMaturity: leg.securityScore >= 85 ? 'High' : leg.securityScore >= 70 ? 'Medium' : 'Developing',
      securityPosture: leg.riskLevel ? `${leg.riskLevel} risk application` : 'Assessed application',
    },
    securityDNA: {
      architecture: leg.technologies.some((t) => /react|vue|angular/i.test(t)) ? 'Frontend Heavy' : 'Web Application',
      exposure: leg.attackSurface.length > 5 ? 'Moderate' : 'Low',
      maturity: leg.securityScore >= 85 ? 'High' : 'Medium',
      attackSurface: leg.attackSurface.length > 8 ? 'Broad' : 'Moderate',
      hardening: leg.securityScore >= 85 ? 'Strong' : 'Needs Improvement',
    },
    attackerPerspective: {
      immediateObservations: [
        ...leg.technologies.slice(0, 3).map((t) => `Technology stack includes ${t}`),
        ...(vulnerabilities[0] ? [`Notable weakness: ${vulnerabilities[0].title}`] : []),
      ],
      mostAttractiveTarget: leg.attackSurface[0] ?? 'Public web entry point',
      probableObjective: 'Credential or session compromise',
      probableRoute:
        leg.attackPaths.map((p) => `${p.source} → ${p.target}`).join(' → ') ||
        'Recon → weakness → impact',
      narrative: `An attacker assessing this target would focus on ${vulnerabilities[0]?.title ?? 'exposed controls'} and the ${leg.technologies.join(', ') || 'web'} stack.`,
    },
    expertAssessment: {
      methodology: 'Upgraded from legacy scan — limited recon depth.',
      assumptions: ['Historical scan data without full threat model pipeline'],
      blindSpots: ['Run a new scan for MITRE mapping, kill-chain, and expert assessment'],
      redTeamVerdict: 'Re-run intelligence pipeline for adversary-grade analysis.',
    },
    defensePriorities: (leg.recommendations ?? []).slice(0, 5).map((action, i) => ({
      rank: i + 1,
      action,
      rationale: 'From prior scan recommendations',
      effort: 'M' as const,
    })),
    reconInsights: {
      trustBoundaries: [],
      exposureZones: [],
      infrastructureSignals: leg.technologies ?? [],
    },
    targetUrl: meta?.targetUrl ?? leg.targetUrl,
    targetTitle: title,
  }

  return {
    ...base,
    platform: buildPlatformIntelligence({ ...base } as import('./types').IntelligenceReport, recon),
  }
}

export function markUpgraded(report: IntelligenceReport): IntelligenceReport & { upgradedFromLegacy?: boolean } {
  return { ...report, upgradedFromLegacy: true }
}
