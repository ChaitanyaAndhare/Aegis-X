import { Link, Outlet, useRouterState } from '@tanstack/react-router'
import { cn } from '@/lib/utils'

const NAV = [
  { to: '/', label: 'Scan' },
  { to: '/history', label: 'History' },
] as const

export function AppShell() {
  const pathname = useRouterState({ select: (s) => s.location.pathname })
  const isRun = pathname.startsWith('/runs/')

  return (
    <div className="flex min-h-screen flex-col bg-background">
      <header className="sticky top-0 z-50 border-b border-border bg-background/90 backdrop-blur-md">
        <div className="ax-container flex h-16 items-center justify-between">
          <Link to="/" className="font-display text-xl tracking-tight">
            AEGIS<span className="text-muted-foreground">—X</span>
          </Link>
          <nav className="hidden items-center gap-1 sm:flex">
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
