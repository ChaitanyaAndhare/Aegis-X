import type { DiscoveryResult } from './types'

export function buildControlsMatrix(discovery: DiscoveryResult): { domain: string; status: 'Good' | 'Fair' | 'Poor'; reasoning: string }[] {
  const hasCsp = Boolean(discovery.headers['content-security-policy'])
  const hasXfo = Boolean(discovery.headers['x-frame-options']) || /frame-ancestors/i.test(discovery.headers['content-security-policy'] ?? '')
  const hasXcto = discovery.headers['x-content-type-options']?.toLowerCase() === 'nosniff'

  return [
    {
      domain: 'Headers',
      status: hasCsp && hasXfo && hasXcto ? 'Good' : hasCsp || hasXfo ? 'Fair' : 'Poor',
      reasoning: hasCsp ? 'CSP observed' : 'CSP not observed',
    },
    {
      domain: 'TLS',
      status: discovery.cleartext ? 'Poor' : discovery.hsts ? 'Good' : 'Fair',
      reasoning: discovery.cleartext ? 'Cleartext HTTP' : discovery.hsts ? 'HSTS present' : 'HTTPS without HSTS',
    },
    {
      domain: 'Cookies',
      status: !discovery.hasCookies
        ? 'Fair'
        : discovery.cookies.every((c) => c.secure && c.httpOnly)
          ? 'Good'
          : 'Poor',
      reasoning: discovery.hasCookies
        ? `${discovery.cookies.length} cookie(s) observed`
        : 'No Set-Cookie on entry response',
    },
    {
      domain: 'Authentication',
      status: discovery.hasAuth ? 'Fair' : 'Fair',
      reasoning: discovery.hasAuth ? 'Auth/login surface reachable' : 'No login surface confirmed',
    },
    {
      domain: 'Session Security',
      status: discovery.authSignals.includes('session') ? 'Fair' : 'Fair',
      reasoning: 'Session handling not fully testable passively',
    },
    {
      domain: 'Transport Security',
      status: discovery.cleartext ? 'Poor' : 'Good',
      reasoning: discovery.cleartext ? 'HTTP entry point' : 'Encrypted transport',
    },
  ]
}
