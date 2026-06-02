import weaknessesKb from '../../../knowledge/kb/weaknesses.json'
import { uuid } from '../store'
import type { CoreAssessment, DiscoveryResult, RuleFinding } from './types'

type WeaknessKb = {
  threats: { id: string; label: string; requiresClientJs?: boolean; requiresCookies?: boolean; requiresApi?: boolean; requiresAuth?: boolean }[]
}

const KB = weaknessesKb as Record<string, WeaknessKb>

export function buildThreatGraph(
  discovery: DiscoveryResult,
  findings: RuleFinding[],
): CoreAssessment['graph'] {
  const nodes: CoreAssessment['graph']['nodes'] = []
  const edges: CoreAssessment['graph']['edges'] = []

  const assetId = 'asset:entry'
  nodes.push({
    id: assetId,
    label: new URL(discovery.finalUrl).hostname,
    type: 'Asset',
    description: `Public entry point (${discovery.statusCode})`,
    evidence: discovery.finalUrl,
  })

  for (const f of findings) {
    const weaknessId = `weakness:${f.weaknessId}`
    nodes.push({
      id: weaknessId,
      label: f.title,
      type: 'Weakness',
      description: f.observedSignal,
      evidence: f.evidenceSummary,
      relatedFindings: [f.id],
    })
    edges.push({
      id: uuid(),
      source: assetId,
      target: weaknessId,
      relation: 'EXPOSES',
      evidence: f.evidenceSummary,
      confidence: f.confidence,
    })

    const kb = KB[f.weaknessId]
    if (!kb) continue

    for (const t of kb.threats) {
      if (t.requiresClientJs && !discovery.hasClientJs) continue
      if (t.requiresCookies && !discovery.hasCookies) continue
      if (t.requiresApi && !discovery.hasApi) continue
      if (t.requiresAuth && !discovery.hasAuth) continue

      const threatId = `threat:${f.weaknessId}:${t.id}`
      nodes.push({
        id: threatId,
        label: t.label,
        type: 'Threat',
        description: `Linked to ${f.title} via knowledge base`,
        evidence: f.evidenceSummary,
        relatedFindings: [f.id],
      })
      edges.push({
        id: uuid(),
        source: weaknessId,
        target: threatId,
        relation: 'ENABLES',
        evidence: f.evidenceSummary,
        confidence: f.confidence,
      })

      const impactId = `impact:${t.id}`
      if (!nodes.some((n) => n.id === impactId)) {
        nodes.push({
          id: impactId,
          label: 'Operational / confidentiality impact',
          type: 'Impact',
          description: 'Potential impact if threat materializes — not verified by active exploit.',
        })
      }
      edges.push({
        id: uuid(),
        source: threatId,
        target: impactId,
        relation: 'IMPACTS',
        evidence: f.potentialImpact,
        confidence: Math.min(f.confidence, 75),
      })
    }
  }

  return { nodes, edges }
}

export function buildAttackPaths(
  discovery: DiscoveryResult,
  findings: RuleFinding[],
  graph: CoreAssessment['graph'],
): CoreAssessment['attackPaths'] {
  const paths: CoreAssessment['attackPaths'] = []

  for (const f of findings.slice(0, 6)) {
    const kb = KB[f.weaknessId]
    const threat = kb?.threats.find(
      (t) =>
        (!t.requiresClientJs || discovery.hasClientJs) &&
        (!t.requiresCookies || discovery.hasCookies) &&
        (!t.requiresApi || discovery.hasApi),
    )
    if (!threat) continue

    paths.push({
      id: `path:${f.id}`,
      name: `${f.title} → ${threat.label}`,
      steps: [
        `Observe: ${f.observedSignal}`,
        `Weakness: ${f.title}`,
        `Threat: ${threat.label}`,
        `Potential impact: ${f.potentialImpact}`,
      ],
      confidence: f.confidence,
    })
  }

  if (!paths.length && graph.nodes.length > 1) {
    paths.push({
      id: 'path:baseline',
      name: 'Limited external exposure',
      steps: ['Passive scan completed', 'No rule-matched weaknesses in assessed scope'],
      confidence: 60,
    })
  }

  return paths
}
