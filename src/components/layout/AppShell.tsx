import { Link, Outlet, useRouterState } from '@tanstack/react-router'
import { useGuest } from '@/lib/guest'
import { cn } from '@/lib/utils'

const NAV = [
  { to: '/', label: 'Scan' },
  { to: '/history', label: 'History' },
] as const

export function AppShell() {
  const { guest, setGuest } = useGuest()
  const pathname = useRouterState({ select: (s) => s.location.pathname })
  const isRun = pathname.startsWith('/runs/')
  const runId = isRun ? pathname.split('/')[2] : null

  return (
    <div className="flex min-h-screen flex-col bg-background">
      <header className="sticky top-0 z-50 border-b border-border bg-background/90 backdrop-blur-md">
        <div className="ax-container flex h-16 items-center justify-between">
          <Link to="/" className="font-display text-xl tracking-tight">
            AEGIS<span className="text-muted-foreground">—X</span>
          </Link>
          <nav className="flex flex-wrap items-center gap-1">
            {NAV.map((item) => (
              <Link
                key={item.to}
                to={item.to}
                className={cn(
                  'rounded-md px-4 py-2 text-sm transition',
                  pathname === item.to || (item.to === '/' && pathname === '/')
                    ? 'bg-foreground text-background'
                    : 'text-muted-foreground hover:text-foreground',
                )}
              >
                {item.label}
              </Link>
            ))}
            {runId && (
              <>
                <Link
                  to="/lab/$runId"
                  params={{ runId }}
                  className="hidden rounded-md px-3 py-2 text-sm text-muted-foreground transition hover:text-foreground sm:inline-block"
                >
                  Lab
                </Link>
                <Link
                  to="/genome/$runId"
                  params={{ runId }}
                  className="hidden rounded-md px-3 py-2 text-sm text-muted-foreground transition hover:text-foreground sm:inline-block"
                >
                  Genome
                </Link>
                <Link
                  to="/digital-twin/$runId"
                  params={{ runId }}
                  className="hidden rounded-md px-3 py-2 text-sm text-muted-foreground transition hover:text-foreground md:inline-block"
                >
                  Twin
                </Link>
              </>
            )}
            <label className="ml-2 flex cursor-pointer items-center gap-1.5 text-xs text-muted-foreground">
              <input
                type="checkbox"
                checked={guest}
                onChange={(e) => setGuest(e.target.checked)}
                className="rounded border-border"
              />
              Guest
            </label>
          </nav>
        </div>
      </header>

      <div className="flex flex-1">
        {isRun && (
          <aside className="hidden w-52 shrink-0 border-r border-border bg-card/50 lg:block">
            <div className="sticky top-16 p-4">
              <p className="ax-label mb-3">Report</p>
              <p className="text-xs text-muted-foreground">Use in-page navigation for sections.</p>
            </div>
          </aside>
        )}

        <main className={cn('min-w-0 flex-1', isRun ? 'lg:pl-0' : '')}>
          <div className={cn('ax-container py-10 md:py-14', isRun && 'max-w-none px-0 py-0')}>
            <Outlet />
          </div>
        </main>
      </div>
    </div>
  )
}
