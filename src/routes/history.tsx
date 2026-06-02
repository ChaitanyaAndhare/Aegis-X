import { createFileRoute, Link } from '@tanstack/react-router'
import { useEffect, useState } from 'react'
import { fetchHistory } from '../lib/api'
import { useGuest } from '../lib/guest'
import type { HistoryEntry } from '../lib/types'

export const Route = createFileRoute('/history')({
  component: HistoryPage,
})

function HistoryPage() {
  const { guest } = useGuest()
  const [entries, setEntries] = useState<HistoryEntry[]>([])

  useEffect(() => {
    fetchHistory(guest).then((d) => setEntries(d.entries)).catch(() => {})
  }, [guest])

  return (
    <div className="space-y-6">
      <h1 className="text-xl font-semibold">History</h1>
      {entries.length === 0 ? (
        <p className="text-sm text-muted-foreground">No completed assessments.</p>
      ) : (
        <ul className="divide-y divide-thm-border border-y border-thm-border">
          {entries.map((e) => (
            <li key={e.runId} className="flex items-center justify-between py-4 text-sm">
              <Link to="/runs/$runId" params={{ runId: e.runId }} className="font-medium hover:text-primary">
                {e.title}
              </Link>
              <span className="tabular-nums text-muted-foreground">
                {e.grade} · {e.securityScore}
              </span>
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}
