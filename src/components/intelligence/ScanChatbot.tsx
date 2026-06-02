import { useEffect, useRef, useState } from 'react'
import { fetchChatHistory, sendChatMessage } from '@/lib/api'
import type { ChatMessage } from '@/lib/types'
import { Loader2, MessageCircle, Send, X } from 'lucide-react'
import { cn } from '@/lib/utils'

export function ScanChatbot({ runId }: { runId: string }) {
  const [open, setOpen] = useState(false)
  const [messages, setMessages] = useState<ChatMessage[]>([])
  const [input, setInput] = useState('')
  const [loading, setLoading] = useState(false)
  const bottomRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (open) fetchChatHistory(runId).then((d) => setMessages(d.messages)).catch(() => {})
  }, [open, runId])

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages, open])

  async function send() {
    const text = input.trim()
    if (!text || loading) return
    setInput('')
    setLoading(true)
    try {
      const r = await sendChatMessage(runId, text)
      setMessages(r.messages)
    } finally {
      setLoading(false)
    }
  }

  return (
    <>
      <button
        type="button"
        onClick={() => setOpen(true)}
        className={cn(
          'fixed bottom-6 right-6 z-40 flex h-12 w-12 items-center justify-center rounded-full bg-primary text-primary-foreground shadow-lg',
          open && 'hidden',
        )}
        aria-label="Open analyst chat"
      >
        <MessageCircle className="h-5 w-5" />
      </button>

      {open && (
        <div className="fixed bottom-6 right-6 z-50 flex h-[min(440px,75vh)] w-[min(360px,calc(100vw-2rem))] flex-col rounded-lg border border-thm-border bg-card shadow-xl">
          <div className="flex items-center justify-between border-b border-thm-border px-4 py-3">
            <p className="text-sm font-semibold">Analyst</p>
            <button type="button" onClick={() => setOpen(false)} className="text-muted-foreground">
              <X className="h-4 w-4" />
            </button>
          </div>
          <div className="flex-1 overflow-y-auto p-3 space-y-2 text-sm">
            {messages.length === 0 && (
              <p className="text-center text-xs text-muted-foreground py-6">Ask about findings or remediation priority.</p>
            )}
            {messages.map((m, i) => (
              <div
                key={i}
                className={cn(
                  'max-w-[92%] rounded-lg px-3 py-2',
                  m.role === 'user' ? 'ml-auto bg-primary text-primary-foreground' : 'bg-[#121820] text-foreground',
                )}
              >
                {m.content}
              </div>
            ))}
            {loading && <Loader2 className="h-4 w-4 animate-spin text-muted-foreground" />}
            <div ref={bottomRef} />
          </div>
          <div className="flex gap-2 border-t border-thm-border p-3">
            <input
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && send()}
              placeholder="Message…"
              className="flex-1 rounded border border-thm-border bg-background px-3 py-2 text-sm focus:border-primary focus:outline-none"
            />
            <button type="button" onClick={send} disabled={loading || !input.trim()} className="thm-btn !px-3">
              <Send className="h-4 w-4" />
            </button>
          </div>
        </div>
      )}
    </>
  )
}
