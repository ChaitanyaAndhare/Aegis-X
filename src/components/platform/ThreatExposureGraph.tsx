import { useCallback, useEffect, useMemo, useRef, useState, type ComponentType } from 'react'
import type { ThreatExposureEdge, ThreatExposureNode } from '@/lib/platform/types'

const TYPE_COLOR: Record<string, string> = {
  Asset: '#9fef00',
  Weakness: '#fbbf24',
  Threat: '#f87171',
  Control: '#34d399',
  Impact: '#a78bfa',
}

type FGNode = ThreatExposureNode & { x?: number; y?: number }

export function ThreatExposureGraph({
  nodes,
  edges,
}: {
  nodes: ThreatExposureNode[]
  edges: ThreatExposureEdge[]
}) {
  const containerRef = useRef<HTMLDivElement>(null)
  const [Graph, setGraph] = useState<ComponentType<Record<string, unknown>> | null>(null)

  useEffect(() => {
    import('react-force-graph-2d').then((m) => setGraph(() => m.default as ComponentType<Record<string, unknown>>))
  }, [])

  const graphData = useMemo(
    () => ({
      nodes: nodes.map((n) => ({ ...n })),
      links: edges.map((e) => ({ ...e, source: e.source, target: e.target })),
    }),
    [nodes, edges],
  )

  const paintNode = useCallback((node: FGNode, ctx: CanvasRenderingContext2D, globalScale: number) => {
    const color = TYPE_COLOR[node.type] ?? '#888'
    ctx.beginPath()
    ctx.arc(node.x!, node.y!, 5, 0, 2 * Math.PI)
    ctx.fillStyle = color
    ctx.fill()
    if (globalScale > 0.8) {
      ctx.font = `${8 / globalScale}px sans-serif`
      ctx.fillStyle = '#9aa5b8'
      ctx.fillText(node.label.slice(0, 20), node.x! + 7, node.y! + 2)
    }
  }, [])

  if (!Graph || !nodes.length) {
    return <p className="py-8 text-center text-xs text-muted-foreground">No graph data.</p>
  }

  return (
    <div ref={containerRef} className="h-[320px]">
      <Graph
        graphData={graphData}
        nodeCanvasObject={paintNode}
        linkColor={() => '#9fef0033'}
        width={containerRef.current?.clientWidth ?? 600}
        height={320}
      />
    </div>
  )
}
