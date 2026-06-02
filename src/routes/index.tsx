import { createFileRoute, Link } from '@tanstack/react-router'
import { useEffect, useState } from 'react'
import { checkHealth, createScan, startRun, listScans } from '../lib/api'
import { useGuest } from '../lib/guest'
import { STACK_HINT_OPTIONS, formatScanDescription } from '@/lib/aegis/parse-hints'
import { Input } from '@/components/ui/input'
import { Alert } from '@/components/ui/alert'
import { cn } from '@/lib/utils'

export const Route = createFileRoute('/')({
  component: HomePage,
})

function HomePage() {
  const { guest } = useGuest()
  const [url, setUrl] = useState('')
  const [github, setGithub] = useState('')
  const [hints, setHints] = useState<string[]>([])
  const [showHints, setShowHints] = useState(false)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [ready, setReady] = useState(false)
  const [recent, setRecent] = useState<{ id: string }[]>([])
  const [authorized, setAuthorized] = useState(false)

  useEffect(() => {
    checkHealth()
      .then((h) => setReady(Boolean(h.ok)))
      .catch((e) => setError(e instanceof Error ? e.message : String(e)))
    listScans(guest)
      .then((d) => setRecent(d.runs.filter((r) => r.finished_at).slice(-5).reverse()))
      .catch(() => {})
  }, [guest])

  async function submit(e: React.FormEvent) {
    e.preventDefault()
    if (!url && !github) {
      setError('Enter an application URL or GitHub repository.')
      return
    }
    if (!ready) {
      setError('API server is not reachable. Start the dev server.')
      return
    }
    if (!authorized) {
      setError('Confirm you are authorized to test this target.')
      return
    }
    setError(null)
    setLoading(true)
    try {
      let title = 'Assessment'
      const fullUrl = url ? (url.startsWith('http') ? url : `https://${url}`) : undefined
      if (fullUrl) {
        try {
          title = new URL(fullUrl).hostname
        } catch {
          title = url
        }
      }
      const { id } = await createScan(
        {
          targetUrl: fullUrl,
          appDescription: formatScanDescription(github || undefined, hints),
          title,
          authorized: true,
        },
        guest,
      )
      const { runId } = await startRun(id, guest)
      window.location.href = `/runs/${runId}`
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="space-y-10">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Automated penetration test</h1>
        <p className="mt-2 text-sm text-muted-foreground">
          Runs like a mid-level external pentester: recon, safe active probes (XSS/SQLi/CORS/redirect/path checks), then
          evidence-backed findings and remediation. Educational payloads only — no destructive testing.
        </p>
      </div>

      <form onSubmit={submit} className="space-y-4">
        <div>
          <label htmlFor="url" className="text-sm font-medium">
            Application URL
          </label>
          <Input
            id="url"
            className="mt-1.5"
            placeholder="example.com"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
          />
        </div>
        <div>
          <label htmlFor="gh" className="text-sm font-medium">
            GitHub <span className="font-normal text-muted-foreground">(optional)</span>
          </label>
          <Input
            id="gh"
            className="mt-1.5"
            placeholder="github.com/org/repo"
            value={github}
            onChange={(e) => setGithub(e.target.value)}
          />
        </div>
        <button
          type="button"
          onClick={() => setShowHints((v) => !v)}
          className="text-xs text-muted-foreground hover:text-foreground"
        >
          {showHints ? 'Hide' : 'Show'} stack hints (optional)
        </button>
        {showHints && (
          <div className="flex flex-wrap gap-2">
            {STACK_HINT_OPTIONS.map((h) => (
              <button
                key={h}
                type="button"
                onClick={() => setHints((p) => (p.includes(h) ? p.filter((x) => x !== h) : [...p, h]))}
                className={cn(
                  'rounded border px-2 py-1 text-xs',
                  hints.includes(h) ? 'border-primary text-primary' : 'border-thm-border text-muted-foreground',
                )}
              >
                {h}
              </button>
            ))}
          </div>
        )}
        <label className="flex cursor-pointer items-start gap-2 text-xs text-muted-foreground">
          <input
            type="checkbox"
            checked={authorized}
            onChange={(e) => setAuthorized(e.target.checked)}
            className="mt-0.5 accent-primary"
          />
          <span>
            I confirm I own this application or have written permission to perform security testing on this URL.
          </span>
        </label>
        {error && <Alert variant="destructive">{error}</Alert>}
        <button type="submit" disabled={loading || !ready || !authorized} className="thm-btn w-full disabled:opacity-50">
          {loading ? 'Pentesting…' : 'Start pentest'}
        </button>
      </form>

      {recent.length > 0 && (
        <div className="border-t border-thm-border pt-6">
          <p className="text-xs font-medium text-muted-foreground">Recent</p>
          <ul className="mt-2 space-y-1 text-sm">
            {recent.map((r) => (
              <li key={r.id}>
                <Link to="/runs/$runId" params={{ runId: r.id }} className="text-primary hover:underline">
                  {r.id.slice(0, 8)}
                </Link>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  )
}
