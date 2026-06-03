import { useCallback, useEffect, useMemo, useRef, useState, type ComponentType } from 'react'
import type { ThreatExposureEdge, ThreatExposureNode } from '@/lib/platform/types'

const TYPE_COLOR: Record<string, string> = {
  Asset: '#171717',
  Weakness: '#ca8a04',
  Threat: '#dc2626',
  Control: '#16a34a',
  Impact: '#7c3aed',
}

type FGNode = ThreatExposureNode & { x?: number; y?: number }

export function ThreatExposureGraph({
  nodes,
  edges,
  height = 400,
}: {
  nodes: ThreatExposureNode[]
  edges: ThreatExposureEdge[]
  height?: number
}) {
  const containerRef = useRef<HTMLDivElement>(null)
  const [dimensions, setDimensions] = useState({ width: 600, height })
  const [Graph, setGraph] = useState<ComponentType<Record<string, unknown>> | null>(null)

  useEffect(() => {
    import('react-force-graph-2d').then((m) =>
      setGraph(() => m.default as ComponentType<Record<string, unknown>>),
    )
  }, [])

  useEffect(() => {
    const el = containerRef.current
    if (!el) return
    const ro = new ResizeObserver((entries) => {
      const { width } = entries[0]?.contentRect ?? { width: 600 }
      setDimensions({ width: Math.floor(width), height })
    })
    ro.observe(el)
    return () => ro.disconnect()
  }, [height])

  const graphData = useMemo(
    () => ({
      nodes: nodes.map((n) => ({ ...n })),
      links: edges.map((e) => ({ ...e, source: e.source, target: e.target })),
    }),
    [nodes, edges],
  )

  const paintNode = useCallback((node: FGNode, ctx: CanvasRenderingContext2D, globalScale: number) => {
    const color = TYPE_COLOR[node.type] ?? '#737373'
    const radius = 4
    ctx.beginPath()
    ctx.arc(node.x!, node.y!, radius, 0, 2 * Math.PI)
    ctx.fillStyle = color
    ctx.fill()
    if (globalScale > 1.2 && node.label) {
      const fontSize = Math.max(9, 11 / globalScale)
      ctx.font = `${fontSize}px Inter, sans-serif`
      ctx.fillStyle = '#525252'
      const label = node.label.length > 18 ? `${node.label.slice(0, 16)}…` : node.label
      ctx.fillText(label, node.x! + radius + 4, node.y! + 3)
    }
  }, [])

  if (!nodes.length) {
    return (
      <div
        className="flex items-center justify-center rounded-lg border border-dashed border-border text-sm text-muted-foreground"
        style={{ height }}
      >
        No graph data
      </div>
    )
  }

  if (!Graph) {
    return (
      <div className="animate-pulse rounded-lg bg-muted" style={{ height }} />
    )
  }

  return (
    <div
      ref={containerRef}
      className="ax-chart-slot w-full rounded-lg border border-border bg-card"
      style={{ height }}
    >
      <Graph
        graphData={graphData}
        nodeCanvasObject={paintNode}
        linkColor={() => 'rgba(0,0,0,0.08)'}
        linkWidth={1}
        width={dimensions.width}
        height={dimensions.height}
        cooldownTicks={80}
        onEngineStop={() => {}}
      />
    </div>
  )
}
