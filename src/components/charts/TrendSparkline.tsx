export function TrendSparkline({
  newCount,
  resolvedCount,
  className = '',
}: {
  newCount: number
  resolvedCount: number
  className?: string
}) {
  const w = 200
  const h = 48
  const baseline = h / 2
  const nY = baseline - Math.min(newCount * 6, baseline - 4)
  const rY = baseline + Math.min(resolvedCount * 6, baseline - 4)

  return (
    <div className={`ax-chart-slot ${className}`} style={{ height: h }}>
      <svg viewBox={`0 0 ${w} ${h}`} className="h-full w-full" preserveAspectRatio="none" aria-hidden>
        <line x1={0} y1={baseline} x2={w} y2={baseline} stroke="hsl(var(--border))" strokeWidth={1} />
        <path
          d={`M 20 ${baseline} Q 70 ${nY} 120 ${nY} T 180 ${baseline}`}
          fill="none"
          stroke="#dc2626"
          strokeWidth={2}
          strokeLinecap="round"
        />
        <path
          d={`M 20 ${baseline} Q 70 ${rY} 120 ${rY} T 180 ${baseline}`}
          fill="none"
          stroke="#16a34a"
          strokeWidth={2}
          strokeLinecap="round"
          opacity={0.85}
        />
      </svg>
    </div>
  )
}
