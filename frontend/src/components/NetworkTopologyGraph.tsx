import { useCallback, useRef, useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import ForceGraph2D from 'react-force-graph-2d'
import { fetchTopologyDemo } from '../data/demoApi'

// --- Types ---

interface TopologyNode {
  device_id: string
  name: string | null
  ip_address: string
  device_type: string | null
}

interface TopologyEdge {
  source_device_id: string
  dest_device_id: string
  protocol: string
  packet_count: number
  last_seen: string
}

interface TopologyResponse {
  nodes: TopologyNode[]
  edges: TopologyEdge[]
  stale: boolean
  last_updated: string | null
}

// Graph data types for react-force-graph
interface GraphNode {
  id: string
  label: string
  ip_address: string
  device_type: string | null
  [key: string]: unknown
}

interface GraphLink {
  source: string
  target: string
  protocol: string
  packet_count: number
  label: string
  [key: string]: unknown
}

interface GraphData {
  nodes: GraphNode[]
  links: GraphLink[]
}

// --- API ---

const isDemoMode = import.meta.env.VITE_DEMO_MODE === 'true'

async function fetchTopology(): Promise<TopologyResponse> {
  if (isDemoMode) {
    return fetchTopologyDemo()
  }
  const res = await fetch('/api/topology')
  if (!res.ok) throw new Error('Failed to fetch topology data')
  return res.json()
}

// --- Color mapping for device types ---

const DEVICE_TYPE_COLORS: Record<string, string> = {
  PLC: '#3b82f6',   // blue
  RTU: '#10b981',   // green
  HMI: '#f59e0b',   // amber
  IED: '#8b5cf6',   // purple
}

const DEFAULT_NODE_COLOR = '#6b7280' // gray

function getNodeColor(deviceType: string | null): string {
  if (!deviceType) return DEFAULT_NODE_COLOR
  return DEVICE_TYPE_COLORS[deviceType] ?? DEFAULT_NODE_COLOR
}

// --- Component ---

export default function NetworkTopologyGraph() {
  const graphRef = useRef(undefined)

  const { data, isLoading, error } = useQuery<TopologyResponse>({
    queryKey: ['topology'],
    queryFn: fetchTopology,
    refetchInterval: isDemoMode ? false : 30_000,
  })

  // Transform API response into react-force-graph format
  const graphData: GraphData = useMemo(() => {
    if (!data) return { nodes: [], links: [] }

    const nodes: GraphNode[] = data.nodes.map((node) => ({
      id: node.device_id,
      label: `${node.ip_address}${node.name ? ` (${node.name})` : ''}`,
      ip_address: node.ip_address,
      device_type: node.device_type,
    }))

    const links: GraphLink[] = data.edges.map((edge) => ({
      source: edge.source_device_id,
      target: edge.dest_device_id,
      protocol: edge.protocol,
      packet_count: edge.packet_count,
      label: `${edge.protocol} (${edge.packet_count})`,
    }))

    return { nodes, links }
  }, [data])

  // Custom node rendering: circle with label
  const drawNode = useCallback(
    (node: GraphNode, ctx: CanvasRenderingContext2D, globalScale: number) => {
      const x = (node as unknown as { x: number }).x
      const y = (node as unknown as { y: number }).y
      if (x == null || y == null) return

      const nodeRadius = 6
      const fontSize = Math.max(10 / globalScale, 1.5)

      // Draw node circle
      ctx.beginPath()
      ctx.arc(x, y, nodeRadius, 0, 2 * Math.PI)
      ctx.fillStyle = getNodeColor(node.device_type)
      ctx.fill()
      ctx.strokeStyle = '#ffffff'
      ctx.lineWidth = 1.5
      ctx.stroke()

      // Draw label below node
      ctx.font = `${fontSize}px sans-serif`
      ctx.textAlign = 'center'
      ctx.textBaseline = 'top'
      ctx.fillStyle = '#1f2937'
      ctx.fillText(node.label, x, y + nodeRadius + 2)
    },
    []
  )

  // Custom link label rendering
  const drawLinkLabel = useCallback(
    (link: GraphLink, ctx: CanvasRenderingContext2D, globalScale: number) => {
      const source = link.source as unknown as { x: number; y: number }
      const target = link.target as unknown as { x: number; y: number }
      if (!source || !target) return

      const midX = (source.x + target.x) / 2
      const midY = (source.y + target.y) / 2
      const fontSize = Math.max(8 / globalScale, 1.2)

      ctx.font = `${fontSize}px sans-serif`
      ctx.textAlign = 'center'
      ctx.textBaseline = 'middle'
      ctx.fillStyle = '#4b5563'
      ctx.fillText(link.label, midX, midY)
    },
    []
  )

  if (isLoading) {
    return (
      <div className="bg-white rounded-lg border border-gray-200 p-6">
        <h2 className="text-lg font-semibold text-gray-900 mb-4">Network Topology</h2>
        <div className="flex items-center justify-center h-64 text-gray-500">
          Loading topology data...
        </div>
      </div>
    )
  }

  if (error) {
    return (
      <div className="bg-white rounded-lg border border-gray-200 p-6">
        <h2 className="text-lg font-semibold text-gray-900 mb-4">Network Topology</h2>
        <div className="flex items-center justify-center h-64 text-red-600">
          Failed to load topology data.
        </div>
      </div>
    )
  }

  const isEmpty = graphData.nodes.length === 0

  return (
    <div className="bg-white rounded-lg border border-gray-200 p-6">
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-lg font-semibold text-gray-900">Network Topology</h2>
        <div className="flex items-center gap-3">
          {data?.stale && (
            <span className="inline-flex items-center rounded-full bg-yellow-100 px-2.5 py-0.5 text-xs font-medium text-yellow-800">
              Stale
            </span>
          )}
          {data?.last_updated && (
            <span className="text-xs text-gray-500">
              Updated: {new Date(data.last_updated).toLocaleString()}
            </span>
          )}
        </div>
      </div>

      {/* Legend */}
      <div className="flex flex-wrap gap-4 mb-4 text-xs text-gray-600">
        {Object.entries(DEVICE_TYPE_COLORS).map(([type, color]) => (
          <div key={type} className="flex items-center gap-1">
            <span
              className="inline-block w-3 h-3 rounded-full"
              style={{ backgroundColor: color }}
            />
            <span>{type}</span>
          </div>
        ))}
        <div className="flex items-center gap-1">
          <span
            className="inline-block w-3 h-3 rounded-full"
            style={{ backgroundColor: DEFAULT_NODE_COLOR }}
          />
          <span>Unknown</span>
        </div>
      </div>

      {isEmpty ? (
        <div className="flex items-center justify-center h-64 text-gray-500">
          No topology data available. Start a scan to discover device relationships.
        </div>
      ) : (
        <div className="border border-gray-100 rounded" style={{ height: '500px' }}>
          <ForceGraph2D
            ref={graphRef}
            graphData={graphData}
            nodeId="id"
            nodeCanvasObject={drawNode}
            nodePointerAreaPaint={(node: GraphNode, color: string, ctx: CanvasRenderingContext2D) => {
              const x = (node as unknown as { x: number }).x
              const y = (node as unknown as { y: number }).y
              if (x == null || y == null) return
              ctx.beginPath()
              ctx.arc(x, y, 8, 0, 2 * Math.PI)
              ctx.fillStyle = color
              ctx.fill()
            }}
            linkDirectionalArrowLength={4}
            linkDirectionalArrowRelPos={0.75}
            linkColor={() => '#d1d5db'}
            linkWidth={1.5}
            linkCanvasObjectMode={() => 'after'}
            linkCanvasObject={drawLinkLabel}
            cooldownTicks={100}
            height={500}
          />
        </div>
      )}
    </div>
  )
}
