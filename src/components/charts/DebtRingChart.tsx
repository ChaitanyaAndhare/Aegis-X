export function DebtRingChart({
  score,
  size = 140,
  className = '',
}: {
  score: number
  size?: number
  className?: string
}) {
  const stroke = 10
  const r = (size - stroke) / 2
  const c = 2 * Math.PI * r
  const offset = c - (score / 100) * c
  const tone = score > 75 ? '#dc2626' : score > 50 ? '#ea580c' : score > 25 ? '#ca8a04' : '#16a34a'

  return (
    <div
      className={`ax-chart-slot flex items-center justify-center ${className}`}
      style={{ width: size, height: size }}
    >
      <svg width={size} height={size} className="-rotate-90" aria-hidden>
        <circle
          cx={size / 2}
          cy={size / 2}
          r={r}
          fill="none"
          stroke="hsl(var(--muted))"
          strokeWidth={stroke}
        />
        <circle
          cx={size / 2}
          cy={size / 2}
          r={r}
          fill="none"
          stroke={tone}
          strokeWidth={stroke}
          strokeDasharray={c}
          strokeDashoffset={offset}
          strokeLinecap="round"
          className="transition-all duration-700 ease-out"
        />
      </svg>
      <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
        <span className="font-display text-3xl tabular-nums">{score}</span>
        <span className="ax-label mt-0.5">Debt</span>
      </div>
    </div>
  )
}
