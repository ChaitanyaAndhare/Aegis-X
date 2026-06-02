import type { DigitalTwinEdge, DigitalTwinGraph, DigitalTwinNode, ReconOutput, ThreatModel, Vulnerability } from '../types'

function nid(type: string, label: string) {
  return `${type}:${label.replace(/\s+/g, '_').slice(0, 40)}`
}

export function buildDigitalTwin(opts: {
  targetUrl?: string
  title: string
  recon: ReconOutput
  vulnerabilities: Vulnerability[]
  threatModel: ThreatModel
}): DigitalTwinGraph {
  const { recon, threatModel, vulnerabilities, title, targetUrl } = opts
  const nodes: DigitalTwinNode[] = []
  const edges: DigitalTwinEdge[] = []
  const rootId = nid('Website', title)
  nodes.push({ id: rootId, type: 'Website', label: title, props: { url: targetUrl ?? 'unknown' } })

  for (const tech of recon.technologies ?? []) {
    const id = nid('Technology', tech)
    nodes.push({ id, type: 'Technology', label: tech })
    edges.push({ id: `e-${rootId}-${id}`, source: rootId, target: id, relation: 'USES' })
  }

  for (const f of recon.findings ?? []) {
    const id = nid('Finding', f.signal)
    nodes.push({ id, type: 'Finding', label: f.signal, props: { detail: f.detail.slice(0, 120) } })
    edges.push({ id: `e-${rootId}-${id}`, source: rootId, target: id, relation: 'EXPOSES' })
  }

  for (const surface of (recon.attackSurface ?? []).slice(0, 12)) {
    const id = nid('Route', surface)
    nodes.push({ id, type: 'Route', label: surface })
    edges.push({ id: `e-${rootId}-${id}`, source: rootId, target: id, relation: 'CONNECTS_TO' })
  }

  const headerFinding = (recon.findings ?? []).find((f) => /header|csp|cookie|tls|hsts/i.test(f.signal + f.detail))
  if (headerFinding) {
    const id = nid('Header', headerFinding.signal)
    nodes.push({ id, type: 'Header', label: headerFinding.signal })
    edges.push({ id: `e-${rootId}-${id}`, source: rootId, target: id, relation: 'EXPOSES' })
  }

  const cookieFinding = (recon.findings ?? []).find((f) => /cookie|session/i.test(f.signal + f.detail))
  if (cookieFinding) {
    const id = nid('Cookie', 'Session/Cookies')
    if (!nodes.find((n) => n.id === id)) {
      nodes.push({ id, type: 'Cookie', label: 'Session/Cookies' })
      edges.push({ id: `e-${rootId}-${id}`, source: rootId, target: id, relation: 'EXPOSES' })
    }
  }

  for (const v of vulnerabilities.slice(0, 8)) {
    const id = nid('Threat', v.title)
    nodes.push({ id, type: 'Threat', label: v.title, props: { severity: v.severity } })
    edges.push({ id: `e-threat-${id}`, source: rootId, target: id, relation: 'INCREASES_RISK' })
    for (const tech of (recon.technologies ?? []).slice(0, 2)) {
      const techId = nid('Technology', tech)
      if (nodes.find((n) => n.id === techId)) {
        edges.push({ id: `e-en-${techId}-${id}`, source: techId, target: id, relation: 'ENABLES' })
      }
    }
  }

  for (const t of (threatModel.threats ?? []).slice(0, 5)) {
    const id = nid('Threat', t.name)
    if (!nodes.find((n) => n.id === id)) {
      nodes.push({ id, type: 'Threat', label: t.name })
      edges.push({ id: `e-tm-${id}`, source: rootId, target: id, relation: 'INCREASES_RISK' })
    }
  }

  return { nodes, edges }
}

export function buildAttackSurfaceMap(recon: ReconOutput, title: string) {
  const attackSurface = recon.attackSurface ?? []
  const technologies = recon.technologies ?? []
  const apis = attackSurface.filter((s) => /api|graphql|rest|endpoint/i.test(s))
  const auth = attackSurface.filter((s) => /login|auth|oauth|session/i.test(s))
  const static_ = attackSurface.filter((s) => /js|css|asset|static|cdn/i.test(s))
  const other = attackSurface.filter((s) => !apis.includes(s) && !auth.includes(s) && !static_.includes(s))

  return {
    root: title,
    branches: [
      { name: 'Frontend', children: other.slice(0, 5).length ? other.slice(0, 5) : ['Web UI'] },
      { name: 'Static Assets', children: static_.length ? static_ : ['JS bundles', 'CSS', 'Media'] },
      { name: 'APIs', children: apis.length ? apis : ['Inferred API layer'] },
      { name: 'Authentication', children: auth.length ? auth : ['Login/session surface'] },
      { name: 'Third-party Dependencies', children: technologies.filter((t) => /cdn|google|cloudflare|analytics/i.test(t)) },
    ],
  }
}
