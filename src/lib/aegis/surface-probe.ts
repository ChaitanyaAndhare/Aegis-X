/**
 * Lightweight passive probes for common paths (backend-only, no user input).
 */

const PROBE_PATHS = [
  '/robots.txt',
  '/sitemap.xml',
  '/.well-known/security.txt',
  '/api/health',
  '/api',
  '/graphql',
  '/login',
  '/signin',
  '/auth/login',
  '/_next/static/chunks/webpack.js',
]

export type ProbeResult = { path: string; status: number; note: string }

export async function probeSurface(baseUrl: string): Promise<ProbeResult[]> {
  let origin: string
  try {
    origin = new URL(baseUrl).origin
  } catch {
    return []
  }

  const results: ProbeResult[] = []
  const batch = PROBE_PATHS.slice(0, 8)

  await Promise.all(
    batch.map(async (path) => {
      try {
        const res = await fetch(`${origin}${path}`, {
          method: 'GET',
          headers: { 'User-Agent': 'AEGIS-X-Surface/1.0' },
          signal: AbortSignal.timeout(4000),
          redirect: 'manual',
        })
        const note =
          res.status === 200
            ? 'reachable'
            : res.status === 301 || res.status === 302
              ? 'redirect'
              : res.status === 401 || res.status === 403
                ? 'protected'
                : `status ${res.status}`
        results.push({ path, status: res.status, note })
      } catch {
        results.push({ path, status: 0, note: 'unreachable' })
      }
    }),
  )

  return results.sort((a, b) => a.path.localeCompare(b.path))
}

export function probesToAttackSurface(probes: ProbeResult[]): string[] {
  return probes
    .filter((p) => p.status > 0 && p.status < 500)
    .map((p) => `${p.path} (${p.note})`)
}

export function probesToFindings(probes: ProbeResult[]) {
  const open = probes.filter((p) => p.status === 200 && /api|graphql|login|signin|auth/i.test(p.path))
  if (!open.length) return []
  return [
    {
      signal: 'Discovered endpoints',
      detail: open.map((p) => `${p.path}: HTTP ${p.status} (${p.note})`).join('; '),
      severity: 'info' as const,
      category: 'surface',
    },
  ]
}
