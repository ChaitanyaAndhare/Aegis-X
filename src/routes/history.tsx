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
    <div className="mx-auto max-w-3xl animate-slide-up">
      <h1 className="font-display text-4xl">History</h1>

      {entries.length === 0 ? (
        <p className="mt-12 text-sm text-muted-foreground">No scans yet.</p>
      ) : (
        <table className="mt-12 w-full text-sm">
          <thead>
            <tr className="border-b border-border text-left ax-label">
              <th className="pb-4 font-medium">Target</th>
              <th className="pb-4 font-medium">Score</th>
              <th className="pb-4 font-medium">Grade</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border">
            {entries.map((e) => (
              <tr key={e.runId} className="group">
                <td className="py-5 pr-4">
                  <Link
                    to="/runs/$runId"
                    params={{ runId: e.runId }}
                    className="font-medium transition group-hover:underline"
                  >
                    {e.title}
                  </Link>
                  {e.targetUrl && (
                    <p className="mt-0.5 truncate text-xs text-muted-foreground">{e.targetUrl}</p>
                  )}
                </td>
                <td className="py-5 tabular-nums text-muted-foreground">{e.securityScore}</td>
                <td className="py-5 font-display text-lg">{e.grade}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  )
}
