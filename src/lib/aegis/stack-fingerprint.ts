/**
 * Deterministic stack / auth detection from fetch data (no user description required).
 */

export type StackFingerprint = {
  frameworks: string[]
  authProviders: string[]
  hosting: string[]
  dataStores: string[]
  clientLibraries: string[]
  attackSurfaceHints: string[]
  exploitFocusAreas: string[]
}

const FRAMEWORK_PATTERNS: [RegExp, string][] = [
  [/__next|_next\/static|next\.js/i, 'Next.js'],
  [/react\.production|react-dom|__REACT/i, 'React'],
  [/vue\.runtime|__vue__/i, 'Vue.js'],
  [/angular|ng-version/i, 'Angular'],
  [/svelte/i, 'Svelte'],
  [/nuxt|__nuxt/i, 'Nuxt'],
  [/gatsby/i, 'Gatsby'],
  [/wordpress|wp-content|wp-includes/i, 'WordPress'],
  [/drupal/i, 'Drupal'],
  [/shopify/i, 'Shopify'],
  [/laravel/i, 'Laravel'],
  [/django/i, 'Django'],
  [/rails|ruby on rails/i, 'Ruby on Rails'],
  [/express|node\.js/i, 'Node.js'],
]

const AUTH_PATTERNS: [RegExp, string][] = [
  [/accounts\.google\.com|gsi\/client|google.*oauth|signin.*google/i, 'Google Sign-In / OAuth'],
  [/login\.microsoftonline|microsoft.*oauth/i, 'Microsoft Entra / OAuth'],
  [/github\.com\/login\/oauth|github.*oauth/i, 'GitHub OAuth'],
  [/auth0\.com|auth0/i, 'Auth0'],
  [/clerk\.|clerk\.accounts/i, 'Clerk'],
  [/firebase.*auth|identitytoolkit/i, 'Firebase Auth'],
  [/cognito|amazoncognito/i, 'AWS Cognito'],
  [/okta\.com|okta/i, 'Okta'],
  [/supabase.*auth/i, 'Supabase Auth'],
  [/passport|next-auth|nextauth/i, 'NextAuth.js'],
]

const HOSTING_PATTERNS: [RegExp, string][] = [
  [/vercel|x-vercel/i, 'Vercel'],
  [/netlify/i, 'Netlify'],
  [/cloudflare|cf-ray/i, 'Cloudflare'],
  [/amazonaws|x-amz/i, 'AWS'],
  [/azure|windows azure/i, 'Azure'],
  [/heroku/i, 'Heroku'],
]

const DATA_PATTERNS: [RegExp, string][] = [
  [/supabase/i, 'Supabase'],
  [/firebase/i, 'Firebase'],
  [/mongodb|mongoose/i, 'MongoDB'],
  [/postgresql|postgres/i, 'PostgreSQL'],
  [/mysql/i, 'MySQL'],
  [/prisma/i, 'Prisma ORM'],
  [/graphql|__apollo/i, 'GraphQL'],
]

const USER_HINT_EXPLOIT: Record<string, string[]> = {
  'Next.js': ['Server-side request forgery via API routes', 'Middleware bypass', 'Source map / build artifact exposure'],
  React: ['Client-side XSS in hydrated components', 'Unsafe dangerouslySetInnerHTML', 'Exposed environment variables'],
  'Google Sign-In / OAuth': ['OAuth redirect URI validation', 'Token leakage in client', 'OpenID state/nonce handling'],
  'Supabase': ['Row Level Security misconfiguration', 'Exposed anon/service keys in client', 'Realtime channel authorization'],
  'GraphQL': ['Introspection enabled', 'Batching/alias abuse', 'Authorization gaps on resolvers'],
  Vercel: ['Serverless function exposure', 'Preview deployment leakage', 'Edge config exposure'],
}

function matchPatterns(blob: string, patterns: [RegExp, string][]): string[] {
  const found = new Set<string>()
  for (const [re, label] of patterns) {
    if (re.test(blob)) found.add(label)
  }
  return [...found]
}

export function fingerprintStack(input: {
  pageHtml?: string
  headers?: string
  probeNotes?: string[]
  userHints?: string[]
}): StackFingerprint {
  const blob = [input.pageHtml ?? '', input.headers ?? '', ...(input.probeNotes ?? [])].join('\n')
  const frameworks = matchPatterns(blob, FRAMEWORK_PATTERNS)
  const authProviders = matchPatterns(blob, AUTH_PATTERNS)
  const hosting = matchPatterns(blob, HOSTING_PATTERNS)
  const dataStores = matchPatterns(blob, DATA_PATTERNS)

  for (const hint of input.userHints ?? []) {
    if (/next/i.test(hint)) frameworks.push('Next.js')
    if (/react/i.test(hint)) frameworks.push('React')
    if (/google|oauth/i.test(hint)) authProviders.push('Google Sign-In / OAuth')
    if (/supabase/i.test(hint)) dataStores.push('Supabase')
    if (/vercel/i.test(hint)) hosting.push('Vercel')
  }

  const uniq = (arr: string[]) => [...new Set(arr)]
  const fw = uniq(frameworks)
  const auth = uniq(authProviders)
  const host = uniq(hosting)
  const data = uniq(dataStores)

  const clientLibraries = fw.filter((f) => /react|vue|angular|svelte/i.test(f))

  const attackSurfaceHints: string[] = []
  if (/\/api\/|graphql|trpc/i.test(blob)) attackSurfaceHints.push('API routes detected')
  if (/<form|type=["']password|sign[\s-]?in/i.test(blob)) attackSurfaceHints.push('Authentication forms present')
  if (/set-cookie|session/i.test(blob)) attackSurfaceHints.push('Session cookies in use')
  if (/_next\/static|chunk|webpack/i.test(blob)) attackSurfaceHints.push('Client bundles exposed')

  const exploitFocusAreas: string[] = []
  for (const label of [...fw, ...auth, ...data, ...host]) {
    const areas = USER_HINT_EXPLOIT[label]
    if (areas) exploitFocusAreas.push(...areas)
  }
  if (!exploitFocusAreas.length && attackSurfaceHints.length) {
    exploitFocusAreas.push('Header and transport hardening', 'Public endpoint authorization review')
  }

  return {
    frameworks: fw,
    authProviders: auth,
    hosting: host,
    dataStores: data,
    clientLibraries: uniq(clientLibraries),
    attackSurfaceHints: uniq(attackSurfaceHints),
    exploitFocusAreas: uniq(exploitFocusAreas).slice(0, 12),
  }
}

export function fingerprintToReconFindings(fp: StackFingerprint) {
  const findings: { signal: string; detail: string; severity?: 'info' | 'medium' | 'low'; category: string }[] = []
  if (fp.frameworks.length) {
    findings.push({
      signal: 'Application framework',
      detail: `Detected: ${fp.frameworks.join(', ')}. Review framework-specific misconfigurations.`,
      severity: 'info',
      category: 'stack',
    })
  }
  if (fp.authProviders.length) {
    findings.push({
      signal: 'Authentication integration',
      detail: `Detected: ${fp.authProviders.join(', ')}. Validate OAuth flows, token storage, and callback URLs.`,
      severity: 'medium',
      category: 'auth',
    })
  }
  if (fp.dataStores.length) {
    findings.push({
      signal: 'Data platform',
      detail: `Detected: ${fp.dataStores.join(', ')}. Review client keys, RLS, and API exposure.`,
      severity: 'info',
      category: 'data',
    })
  }
  return findings
}

export function formatFingerprintForAgents(fp: StackFingerprint): string {
  return `## Deterministic stack profile (verify against evidence)
Frameworks: ${fp.frameworks.join(', ') || 'none detected'}
Auth: ${fp.authProviders.join(', ') || 'none detected'}
Hosting: ${fp.hosting.join(', ') || 'none detected'}
Data: ${fp.dataStores.join(', ') || 'none detected'}
Surface hints: ${fp.attackSurfaceHints.join('; ') || 'none'}
Prioritize exploit analysis for:
${fp.exploitFocusAreas.map((a) => `- ${a}`).join('\n') || '- Standard web application controls'}`
}
