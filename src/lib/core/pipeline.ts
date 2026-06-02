import { runPentest } from '../pentest/runner'
import { factsFromDiscovery } from './evidence'
import { evaluateRules } from './rules'
import { buildAttackPaths, buildThreatGraph } from './threat'
import { computeRiskMetrics } from './risk'
import { buildRoadmap } from './roadmap'
import { buildControlsMatrix } from './controls'
import { addPentestFacts, mergeFindings, pentestToRuleFindings } from './pentest-merge'
import type { CoreAssessment } from './types'

/** Pipeline: pentest first, then intelligence layers */
export const PIPELINE_STEPS = [
  'pentest',
  'evidence',
  'rules',
  'threat',
  'risk',
  'roadmap',
] as const

/** @deprecated alias */
export const DETERMINISTIC_STEPS = PIPELINE_STEPS

export async function runDeterministicAssessment(opts: {
  scanId: string
  targetUrl: string
  targetTitle: string
}): Promise<CoreAssessment> {
  const started = Date.now()

  const pentest = await runPentest(opts.targetUrl)
  const discovery = pentest.discovery

  let facts = factsFromDiscovery(discovery)
  facts = addPentestFacts(facts, pentest.findings, discovery.finalUrl)

  const passiveFindings = evaluateRules(discovery, facts)
  const activeFindings = pentestToRuleFindings(pentest.findings)
  const findings = mergeFindings(passiveFindings, activeFindings)

  const graph = buildThreatGraph(discovery, findings)
  const attackPaths = buildAttackPaths(discovery, findings, graph)
  const risk = computeRiskMetrics(discovery, findings, facts.length, pentest.findings)
  const remediation = buildRoadmap(findings)
  const controls = buildControlsMatrix(discovery)

  const verified = pentest.findings.filter((f) => f.status === 'verified').length

  return {
    scanId: opts.scanId,
    targetUrl: discovery.finalUrl,
    targetTitle: opts.targetTitle,
    scannedAt: new Date().toISOString(),
    durationMs: Date.now() - started,
    pentest,
    facts,
    discovery,
    findings,
    graph,
    riskScore: risk.riskScore,
    grade: risk.grade,
    riskLevel: risk.riskLevel,
    securityDebt: risk.securityDebt,
    coveragePercent: risk.coveragePercent,
    confidencePercent: risk.confidencePercent,
    observedPosture: {
      label: risk.observedPosture.label,
      summary: `${risk.observedPosture.summary} Active pentest: ${pentest.checksRun.length} checks, ${pentest.requestCount} requests, ${verified} verified issue(s). ${pentest.methodology}`,
    },
    attackPaths,
    remediation,
    controls,
    assetsInventory: discovery.assets,
  }
}
