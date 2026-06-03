import { createFileRoute, Link } from '@tanstack/react-router'
import { useEffect, useState } from 'react'
import { checkHealth, createScan, startRun, listScans } from '../lib/api'
import { useGuest } from '../lib/guest'
import { STACK_HINT_OPTIONS, formatScanDescription } from '@/lib/aegis/parse-hints'
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
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [ready, setReady] = useState(false)
  const [recent, setRecent] = useState<{ id: string }[]>([])
  const [authorized, setAuthorized] = useState(false)
  const [orgType, setOrgType] = useState<'Fintech' | 'Healthcare' | 'SaaS' | 'Startup' | 'Ecommerce' | 'Government'>('SaaS')

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
    if (!url.trim()) {
      setError('Enter a URL.')
      return
    }
    if (!ready) {
      setError('API unavailable.')
      return
    }
    if (!authorized) {
      setError('Authorization required.')
      return
    }
    setError(null)
    setLoading(true)
    try {
      const fullUrl = url.startsWith('http') ? url : `https://${url}`
      let title = fullUrl
      try {
        title = new URL(fullUrl).hostname
      } catch {
        /* keep */
      }
      const { id } = await createScan(
        {
          targetUrl: fullUrl,
          appDescription: formatScanDescription(github || undefined, hints),
          title,
          authorized: true,
          orgType,
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
    <div className="mx-auto max-w-xl animate-slide-up">
      <h1 className="ax-display">
        Scan fast.
        <br />
        <span className="text-muted-foreground">Prove every finding.</span>
      </h1>

      <form onSubmit={submit} className="mt-14 space-y-8">
        <Field label="Target">
          <input
            id="url"
            className="w-full border-0 border-b border-border bg-transparent py-3 text-lg outline-none transition focus:border-foreground"
            placeholder="example.com"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            autoComplete="url"
          />
        </Field>

        <Field label="Risk profile">
          <select
            className="w-full border-0 border-b border-border bg-transparent py-3 text-sm outline-none focus:border-foreground"
            value={orgType}
            onChange={(e) => setOrgType(e.target.value as typeof orgType)}
          >
            {(['SaaS', 'Fintech', 'Healthcare', 'Startup', 'Ecommerce', 'Government'] as const).map((o) => (
              <option key={o} value={o}>
                {o}
              </option>
            ))}
          </select>
        </Field>

        <details className="text-sm text-muted-foreground">
          <summary className="cursor-pointer hover:text-foreground">Advanced</summary>
          <div className="mt-4 space-y-4">
            <input
              className="w-full border-b border-border bg-transparent py-2 text-sm outline-none"
              placeholder="GitHub (optional)"
              value={github}
              onChange={(e) => setGithub(e.target.value)}
            />
            <div className="flex flex-wrap gap-2">
              {STACK_HINT_OPTIONS.map((h) => (
                <button
                  key={h}
                  type="button"
                  onClick={() => setHints((p) => (p.includes(h) ? p.filter((x) => x !== h) : [...p, h]))}
                  className={cn(
                    'rounded-full border px-3 py-1 text-xs transition',
                    hints.includes(h) ? 'border-foreground bg-foreground text-background' : 'border-border',
                  )}
                >
                  {h}
                </button>
              ))}
            </div>
          </div>
        </details>

        <label className="flex cursor-pointer items-start gap-3 text-sm text-muted-foreground">
          <input
            type="checkbox"
            checked={authorized}
            onChange={(e) => setAuthorized(e.target.checked)}
            className="mt-1 rounded border-border"
          />
          <span>I am authorized to test this target.</span>
        </label>

        {error && <Alert variant="destructive">{error}</Alert>}

        <button type="submit" disabled={loading || !ready || !authorized} className="ax-btn w-full">
          {loading ? 'Scanning' : 'Start scan'}
        </button>
      </form>

      {recent.length > 0 && (
        <div className="mt-20 border-t border-border pt-10">
          <p className="ax-label">Recent</p>
          <ul className="mt-4 space-y-2">
            {recent.map((r) => (
              <li key={r.id}>
                <Link
                  to="/runs/$runId"
                  params={{ runId: r.id }}
                  className="text-sm text-muted-foreground transition hover:text-foreground"
                >
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

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <label className="ax-label">{label}</label>
      <div className="mt-2">{children}</div>
    </div>
  )
}
