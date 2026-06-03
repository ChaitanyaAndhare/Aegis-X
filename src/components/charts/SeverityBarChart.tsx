import type { Severity } from '@/backend/core/types'

const ORDER: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
const COLORS: Record<Severity, string> = {
  CRITICAL: '#dc2626',
  HIGH: '#ea580c',
  MEDIUM: '#ca8a04',
  LOW: '#2563eb',
  INFO: '#a3a3a3',
}

export function SeverityBarChart({
  counts,
  className = '',
}: {
  counts: Record<Severity, number>
  className?: string
}) {
  const max = Math.max(1, ...ORDER.map((s) => counts[s]))
  const w = 280
  const h = 160
  const pad = { t: 8, r: 8, b: 28, l: 8 }
  const innerW = w - pad.l - pad.r
  const innerH = h - pad.t - pad.b
  const barW = innerW / ORDER.length - 10

  return (
    <div className={`ax-chart-slot ${className}`} style={{ height: h }}>
      <svg
        viewBox={`0 0 ${w} ${h}`}
        className="h-full w-full"
        preserveAspectRatio="xMidYMid meet"
        role="img"
        aria-label="Findings by severity"
      >
        {ORDER.map((sev, i) => {
          const val = counts[sev]
          const barH = (val / max) * innerH
          const x = pad.l + i * (innerW / ORDER.length) + 5
          const y = pad.t + innerH - barH
          return (
            <g key={sev}>
              <rect
                x={x}
                y={y}
                width={barW}
                height={Math.max(val > 0 ? 4 : 0, barH)}
                rx={2}
                fill={COLORS[sev]}
                className="transition-all duration-500"
              />
              <text
                x={x + barW / 2}
                y={h - 8}
                textAnchor="middle"
                className="fill-muted-foreground text-[9px]"
                style={{ fontFamily: 'Inter, sans-serif' }}
              >
                {sev.slice(0, 1)}
              </text>
            </g>
          )
        })}
      </svg>
    </div>
  )
}
