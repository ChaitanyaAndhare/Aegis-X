import { fingerprintStack } from '../aegis/stack-fingerprint'
import { probeSurface } from '../aegis/surface-probe'
import { uuid } from '../store'
import type { DiscoveryResult } from './types'

function headerMap(res: Response): Record<string, string> {
  const out: Record<string, string> = {}
  res.headers.forEach((v, k) => {
    out[k.toLowerCase()] = v
  })
  return out
}

function parseCookies(setCookie: string | null): DiscoveryResult['cookies'] {
  if (!setCookie) return []
  const parts = setCookie.split(/,(?=\s*\w+=)/)
  return parts.map((chunk) => {
    const name = chunk.split('=')[0]?.trim() ?? 'unknown'
    const lower = chunk.toLowerCase()
    return {
      name,
      secure: lower.includes('secure'),
      httpOnly: lower.includes('httponly'),
      sameSite: /samesite=(\w+)/i.exec(chunk)?.[1] ?? null,
    }
  })
}

function extractAssets(html: string, base: URL): DiscoveryResult['assets'] {
  const assets: DiscoveryResult['assets'] = [{ kind: 'page', path: base.pathname || '/' }]
  const scriptRe = /<script[^>]+src=["']([^"']+)["']/gi
  const linkRe = /<link[^>]+href=["']([^"']+)["']/gi
  let m: RegExpExecArray | null
  while ((m = scriptRe.exec(html))) {
    try {
      assets.push({ kind: 'script', path: new URL(m[1], base).pathname })
    } catch {
      assets.push({ kind: 'script', path: m[1] })
    }
  }
  while ((m = linkRe.exec(html))) {
    if (!/\.css/i.test(m[1]) && !/stylesheet/i.test(m[0])) continue
    try {
      assets.push({ kind: 'stylesheet', path: new URL(m[1], base).pathname })
    } catch {
      assets.push({ kind: 'stylesheet', path: m[1] })
    }
  }
  return assets.slice(0, 80)
}

function extractForms(html: string): DiscoveryResult['forms'] {
  const forms: DiscoveryResult['forms'] = []
  const formRe = /<form[^>]*>([\s\S]*?)<\/form>/gi
  let m: RegExpExecArray | null
  while ((m = formRe.exec(html))) {
    const block = m[0]
    const action = /action=["']([^"']*)["']/i.exec(block)?.[1] ?? ''
    const hasPassword = /type=["']password["']/i.test(block)
    forms.push({ action, hasPassword })
  }
  return forms.slice(0, 20)
}

function authSignalsFrom(html: string, headers: Record<string, string>, cookies: DiscoveryResult['cookies']): string[] {
  const signals = new Set<string>()
  if (cookies.length) signals.add('cookies')
  if (/bearer|jwt|eyJ[a-zA-Z0-9_-]+\./i.test(html)) signals.add('jwt')
  if (/oauth|openid|accounts\.google|login\.microsoftonline|auth0/i.test(html)) signals.add('oauth')
  if (/session|connect\.sid|PHPSESSID/i.test(html + JSON.stringify(headers))) signals.add('session')
  return [...signals]
}

export async function runDiscovery(targetUrl: string): Promise<DiscoveryResult> {
  const parsed = new URL(targetUrl.startsWith('http') ? targetUrl : `https://${targetUrl}`)
  if (!['http:', 'https:'].includes(parsed.protocol)) {
    throw new Error('URL must use http or https')
  }

  const res = await fetch(parsed.href, {
    headers: { 'User-Agent': 'AEGIS-X-Core/1.0' },
    signal: AbortSignal.timeout(12000),
    redirect: 'follow',
  })

  const finalUrl = res.url
  const headers = headerMap(res)
  const html = await res.text()
  const base = new URL(finalUrl)
  const setCookie = res.headers.get('set-cookie')
  const cookies = parseCookies(setCookie)
  const probes = await probeSurface(finalUrl)
  const fingerprint = fingerprintStack({
    pageHtml: html,
    headers: Object.entries(headers)
      .map(([k, v]) => `${k}: ${v}`)
      .join('\n'),
    probeNotes: probes.map((p) => `${p.path} ${p.status}`),
  })

  const technologies = [
    ...fingerprint.frameworks,
    ...fingerprint.hosting,
    ...fingerprint.authProviders,
  ]
  const assets = extractAssets(html, base)
  const forms = extractForms(html)
  const authSignals = authSignalsFrom(html, headers, cookies)
  const cleartext = parsed.protocol === 'http:'
  const hsts = Boolean(headers['strict-transport-security'])
  const hasClientJs = assets.some((a) => a.kind === 'script') || /react|vue|angular|svelte/i.test(html)
  const hasApi = probes.some((p) => /\/api|graphql/i.test(p.path) && p.status > 0 && p.status < 500)
  const hasAuth = probes.some((p) => /login|signin|auth/i.test(p.path) && p.status > 0) || forms.some((f) => f.hasPassword)
  const serverDisclosed = Boolean(headers.server || headers['x-powered-by'])

  for (const p of probes.filter((x) => x.status === 200 || x.status === 301 || x.status === 302)) {
    assets.push({ kind: 'route', path: p.path })
  }

  return {
    targetUrl: parsed.href,
    finalUrl,
    pageHtml: html.slice(0, 200_000),
    statusCode: res.status,
    headers,
    cookies,
    technologies: [...new Set(technologies)],
    assets,
    forms,
    authSignals,
    probes: probes.map((p) => ({ path: p.path, status: p.status, note: p.note })),
    cleartext,
    hsts,
    hasClientJs,
    hasApi,
    hasAuth,
    hasCookies: cookies.length > 0,
    serverDisclosed,
  }
}

export function discoveryFactId(): string {
  return uuid()
}
