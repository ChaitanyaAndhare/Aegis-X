import { Link, Outlet } from '@tanstack/react-router'
import { useGuest } from '@/lib/guest'
import { Shield } from 'lucide-react'
import { cn } from '@/lib/utils'

export function AppShell() {
  const { guest, setGuest } = useGuest()

  return (
    <div className="min-h-screen bg-background">
      <header className="border-b border-thm-border">
        <div className="mx-auto flex max-w-6xl items-center justify-between gap-4 px-6 py-4">
          <Link to="/" className="flex items-center gap-2 font-semibold">
            <Shield className="h-5 w-5 text-primary" />
            AEGIS-X
          </Link>
          <nav className="flex items-center gap-4 text-sm">
            <Link to="/" className={cn('text-muted-foreground hover:text-foreground', '[&.active]:text-primary')}>
              Assess
            </Link>
            <Link to="/history" className={cn('text-muted-foreground hover:text-foreground', '[&.active]:text-primary')}>
              History
            </Link>
            <label className="flex cursor-pointer items-center gap-1.5 text-xs text-muted-foreground">
              <input type="checkbox" checked={guest} onChange={(e) => setGuest(e.target.checked)} className="accent-primary" />
              Guest
            </label>
          </nav>
        </div>
      </header>
      <main className="mx-auto max-w-6xl px-6 py-8">
        <Outlet />
      </main>
    </div>
  )
}
