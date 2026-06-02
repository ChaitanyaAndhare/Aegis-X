export const STACK_HINT_OPTIONS = [
  'Next.js',
  'React',
  'Google Sign-In',
  'Supabase',
  'Vercel',
  'GraphQL API',
] as const

export type StackHint = (typeof STACK_HINT_OPTIONS)[number]

export function formatScanDescription(githubUrl?: string, hints?: string[]): string {
  const parts: string[] = ['Automated external security assessment.']
  if (hints?.length) parts.push(`Stack hints (validate against evidence): ${hints.join(', ')}`)
  if (githubUrl) parts.push(`GitHub repository: ${githubUrl}`)
  return parts.join('\n')
}

export function parseStackHints(description: string): string[] {
  const m = description.match(/Stack hints[^:]*:\s*([^\n]+)/i)
  if (!m) return []
  return m[1]!.split(',').map((s) => s.trim()).filter(Boolean)
}

export function parseGitHubFromDescription(description: string): string | undefined {
  const m = description.match(/GitHub repository:\s*(https:\/\/github\.com\/[^\s]+)/i)
  return m?.[1]
}
