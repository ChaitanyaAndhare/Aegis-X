import { discoveryFactId } from './discovery'
import type { DiscoveryResult, EvidenceFact } from './types'

export function factsFromDiscovery(discovery: DiscoveryResult): EvidenceFact[] {
  const at = new Date().toISOString()
  const source = discovery.finalUrl
  const facts: EvidenceFact[] = []

  for (const [name, value] of Object.entries(discovery.headers)) {
    facts.push({
      id: discoveryFactId(),
      type: 'header',
      name,
      value,
      source,
      observedAt: at,
    })
  }

  for (const c of discovery.cookies) {
    facts.push({
      id: discoveryFactId(),
      type: 'cookie',
      name: c.name,
      value: `secure=${c.secure}; httponly=${c.httpOnly}; samesite=${c.sameSite ?? 'unset'}`,
      source,
      observedAt: at,
    })
  }

  for (const tech of discovery.technologies) {
    facts.push({
      id: discoveryFactId(),
      type: 'technology',
      name: tech,
      value: null,
      source,
      observedAt: at,
    })
  }

  for (const asset of discovery.assets.slice(0, 40)) {
    facts.push({
      id: discoveryFactId(),
      type: 'asset',
      name: asset.kind,
      value: asset.path,
      source,
      observedAt: at,
    })
  }

  facts.push({
    id: discoveryFactId(),
    type: 'tls',
    name: 'transport',
    value: discovery.cleartext ? 'http' : 'https',
    source,
    observedAt: at,
  })

  facts.push({
    id: discoveryFactId(),
    type: 'tls',
    name: 'hsts',
    value: discovery.hsts ? 'present' : 'absent',
    source,
    observedAt: at,
  })

  facts.push({
    id: discoveryFactId(),
    type: 'http',
    name: 'status',
    value: String(discovery.statusCode),
    source,
    observedAt: at,
  })

  for (const probe of discovery.probes) {
    facts.push({
      id: discoveryFactId(),
      type: 'http',
      name: `probe:${probe.path}`,
      value: `${probe.status} (${probe.note})`,
      source,
      observedAt: at,
    })
  }

  for (const form of discovery.forms) {
    facts.push({
      id: discoveryFactId(),
      type: 'form',
      name: form.hasPassword ? 'login' : 'form',
      value: form.action || '/',
      source,
      observedAt: at,
    })
  }

  for (const signal of discovery.authSignals) {
    facts.push({
      id: discoveryFactId(),
      type: 'auth',
      name: signal,
      value: null,
      source,
      observedAt: at,
    })
  }

  return facts
}
