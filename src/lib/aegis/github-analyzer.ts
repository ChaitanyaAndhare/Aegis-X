/** Fetch public GitHub repo files for supply-chain signals (no token). */
export async function analyzeGitHubRepo(repoUrl: string): Promise<{ summary: string; signals: string[] }> {
  const signals: string[] = []
  try {
    const parsed = new URL(repoUrl)
    if (!parsed.hostname.includes('github.com')) {
      return { summary: 'Not a GitHub URL', signals: [] }
    }
    const parts = parsed.pathname.replace(/^\//, '').split('/').filter(Boolean)
    if (parts.length < 2) return { summary: 'Invalid repo path', signals: [] }
    const [owner, repo] = parts
    const base = `https://raw.githubusercontent.com/${owner}/${repo}/HEAD`

    const files = ['package.json', 'Dockerfile', '.github/workflows/ci.yml', 'requirements.txt', 'go.mod']
    for (const file of files) {
      try {
        const res = await fetch(`${base}/${file}`, { signal: AbortSignal.timeout(5000) })
        if (!res.ok) continue
        const text = await res.text()
        if (file === 'package.json') {
          signals.push('package.json present — review dependencies and scripts')
          if (/"(express|react|next|axios)"/.test(text)) signals.push('Node/web stack detected in package.json')
          if (/"scripts":/.test(text) && /test|lint|audit/.test(text)) signals.push('CI scripts may include test/lint')
          else signals.push('No obvious security scripts in package.json')
        }
        if (file === 'Dockerfile') {
          signals.push('Dockerfile found — review base image and exposed ports')
          if (/latest/i.test(text)) signals.push('Dockerfile uses floating tags (latest)')
        }
        if (file.includes('workflow')) {
          signals.push('GitHub Actions workflow detected')
          if (/secrets\./i.test(text)) signals.push('Workflow references secrets — verify least privilege')
        }
      } catch {
        /* skip file */
      }
    }

    return {
      summary: signals.length ? `GitHub analysis: ${owner}/${repo}` : `No key manifests found in ${owner}/${repo}`,
      signals,
    }
  } catch {
    return { summary: 'GitHub analysis failed', signals: [] }
  }
}

export function extractGitHubUrl(text: string): string | undefined {
  const m = text.match(/https?:\/\/github\.com\/[\w.-]+\/[\w.-]+/i)
  return m?.[0]
}
