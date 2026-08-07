import React, { useEffect, useState, useMemo } from 'react'
import {
  ReactFlow, Background, Controls, Panel, type Node, type Edge,
  Handle, Position, useReactFlow
} from '@xyflow/react'
import '@xyflow/react/dist/style.css'
import { api } from '../api/client'
import { getCategoryColor, getCategoryIcon } from '../utils/theme'
import CopyButton from './CopyButton'

function GraphCameraController({ selectedNodeId, nodes }: { selectedNodeId: string | null, nodes: Node[] }) {
  const { setCenter, getZoom, fitView } = useReactFlow()
  const nodeIds = nodes.map(n => n.id).join(',')
  
  useEffect(() => {
    if (nodes.length === 0) return

    if (selectedNodeId) {
      const node = nodes.find(n => n.id === selectedNodeId)
      if (node) {
        const zoom = getZoom()
        const x = node.position.x + 110 + (250 / zoom)
        const y = node.position.y + 35
        setCenter(x, y, { zoom, duration: 500 })
      }
    } else {
      window.requestAnimationFrame(() => fitView({ padding: 0.2, duration: 500 }))
    }
  }, [selectedNodeId, nodeIds, setCenter, getZoom, fitView])
  
  return null
}

interface BlastNode {
  id: string
  type: string
  category: string
  label: string
  raw?: any
}

const baseNodeStyle: React.CSSProperties = {
  display: 'flex', alignItems: 'center', gap: 8, padding: '8px 12px',
  borderRadius: 8, fontSize: 11, fontWeight: 600, maxWidth: 220,
  background: 'var(--bg)', border: '1px solid var(--border)',
  boxShadow: 'var(--shadow-sm)',
}

const RootNode = ({ data }: { data: any }) => (
  <div className="hoverable-node" style={{ ...baseNodeStyle, border: '2px solid var(--crit)', background: 'var(--crit-bg)', color: 'var(--crit)' }}>
    <Handle type="source" position={Position.Top} id="top" style={{ opacity: 0 }} />
    <Handle type="source" position={Position.Right} id="right" style={{ opacity: 0 }} />
    <Handle type="source" position={Position.Bottom} id="bottom" style={{ opacity: 0 }} />
    <Handle type="source" position={Position.Left} id="left" style={{ opacity: 0 }} />
    {getCategoryIcon('root', 14, 'var(--crit)')}
    <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{data.label}</span>
  </div>
)

const TelemetryNode = ({ data }: { data: any }) => {
  const color = getCategoryColor(data.category)
  return (
    <div className="hoverable-node" style={{ ...baseNodeStyle, borderColor: color, color: color }}>
      <Handle type="target" position={Position.Top} id="top" style={{ opacity: 0 }} />
      <Handle type="target" position={Position.Right} id="right" style={{ opacity: 0 }} />
      <Handle type="target" position={Position.Bottom} id="bottom" style={{ opacity: 0 }} />
      <Handle type="target" position={Position.Left} id="left" style={{ opacity: 0 }} />
      {getCategoryIcon(data.category, 13, color)}
      <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{data.label}</span>
    </div>
  )
}

const nodeTypes = { root: RootNode, telemetry: TelemetryNode }

function radialLayout(items: BlastNode[]): Node[] {
  const root = items.find(n => n.type === 'root')
  const rest = items.filter(n => n.type !== 'root')
  if (!root) return []

  const cx = 400, cy = 300
  const radius = Math.max(320, rest.length * 40)

  const nodes: Node[] = [
    { id: root.id, type: 'root', position: { x: cx - 110, y: cy - 20 }, data: { label: root.label, raw: root.raw, category: root.category } },
  ]

  rest.forEach((n, i) => {
    const angle = (i / rest.length) * 2 * Math.PI
    let sourceHandle = 'right', targetHandle = 'left'
    if (angle >= Math.PI / 4 && angle < 3 * Math.PI / 4) { sourceHandle = 'bottom'; targetHandle = 'top' }
    else if (angle >= 3 * Math.PI / 4 && angle < 5 * Math.PI / 4) { sourceHandle = 'left'; targetHandle = 'right' }
    else if (angle >= 5 * Math.PI / 4 && angle < 7 * Math.PI / 4) { sourceHandle = 'top'; targetHandle = 'bottom' }

    nodes.push({
      id: n.id,
      type: 'telemetry',
      position: { x: cx + radius * Math.cos(angle) - 110, y: cy + radius * Math.sin(angle) - 20 },
      data: { label: n.label, sourceHandle, targetHandle, category: n.category, raw: n.raw },
    })
  })
  return nodes
}

export default function BlastRadius({ rootGuid, rootLabel = 'Suspicious Process' }: { rootGuid: string, rootLabel?: string }) {
  const [events, setEvents] = useState<any[]>([])
  const [loading, setLoading] = useState(true)
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null)

  useEffect(() => {
    if (!rootGuid) return
    setSelectedNodeId(null)
    setLoading(true)
    // Dynamic: passing 'all' allows the backend 1=1 filter to return all types of pivot events
    api.getPivotEvents(rootGuid, 'all')
      .then(res => setEvents((res.events as any[]).slice(0, 45)))
      .catch(console.error)
      .finally(() => setLoading(false))
  }, [rootGuid])

  const { nodes, edges } = useMemo(() => {
    const items: BlastNode[] = [{ id: 'root', type: 'root', category: 'root', label: rootLabel || 'Suspicious Process', raw: { isRoot: true, guid: rootGuid } }]
    
    const seen = new Set<string>()
    events.forEach((e: any, i) => {
      let category = e.event_type ? e.event_type.toLowerCase() : 'other'
      if (category === 'other') {
        if (e.__eid === 3) category = 'network'
        else if (e.__eid === 11 || e.__eid === 23) category = 'file'
        else if (e.__eid === 12 || e.__eid === 13 || e.__eid === 14) category = 'registry'
        else if (e.__eid === 22) category = 'dns'
        else if (e.__eid === 1 || e.__eid === 5) category = 'process'
      }
      let label = e.TargetFilename || e.TargetObject || e.DestinationIp || e.QueryName || e.QUERYNAME || e.Image
      
      if (!label) {
        // Dynamic fallback: find the first descriptive string field for completely unknown log types
        const skip = ['__eid', '__ts', 'event_type', 'ProcessGuid', 'ParentProcessGuid', 'RuleName', 'UtcTime', 'ProcessId', 'SourceProcessId', 'EventID', 'Channel']
        for (const [k, v] of Object.entries(e)) {
          if (!skip.includes(k) && typeof v === 'string' && v.trim().length > 0) {
            label = v
            break
          }
        }
      }
      label = label || `Event ${e.__eid || category}`
      
      const cleanLabel = String(label).split('\\').pop() || String(label)
      
      if (seen.has(cleanLabel)) return
      seen.add(cleanLabel)
      items.push({ id: `node-${i}`, type: 'telemetry', category, label: cleanLabel, raw: e })
    })

    const rfNodes = radialLayout(items)
    const rfEdges: Edge[] = items.filter(n => n.type !== 'root').map(n => {
      const nodeLayout = rfNodes.find(x => x.id === n.id)
      return {
        id: `e-root-${n.id}`, source: 'root', target: n.id,
        sourceHandle: nodeLayout?.data?.sourceHandle as string | undefined,
        targetHandle: nodeLayout?.data?.targetHandle as string | undefined,
        animated: true,
        style: {
          stroke: getCategoryColor(n.category),
          strokeWidth: 1.5,
        }
      }
    })
    return { nodes: rfNodes, edges: rfEdges }
  }, [rootLabel, events, rootGuid])

  // Derive unique categories present in the graph for the legend
  const uniqueCategories = Array.from(new Set(nodes.filter(n => n.type !== 'root').map(n => n.data.category as string)))

  return (
    <div style={{ flex: 1, position: 'relative', background: 'var(--bg-2)', height: '100%' }}>
      {loading && <div style={{ position: 'absolute', top: 16, left: '50%', transform: 'translateX(-50%)', zIndex: 10, background: 'var(--bg)', padding: '6px 14px', borderRadius: 99, border: '1px solid var(--border)', fontSize: 12, color: 'var(--text-2)', boxShadow: 'var(--shadow)' }}>Loading blast radius…</div>}
      <ReactFlow nodes={nodes} edges={edges} nodeTypes={nodeTypes} onPaneClick={() => setSelectedNodeId(null)} onNodeClick={(_, node) => {
        if (node.id === selectedNodeId) setSelectedNodeId(null)
        else setSelectedNodeId(node.id)
      }} nodesDraggable={true} nodesConnectable={false} elementsSelectable={true} minZoom={0.1} maxZoom={2} fitView proOptions={{ hideAttribution: true }}>
        <Background variant="cross" color="var(--border)" gap={24} size={2} />
        <Controls showInteractive={true} />
        <Panel position="bottom-right" style={{ background: 'var(--bg)', padding: '8px 12px', borderRadius: 8, border: '1px solid var(--border)', fontSize: 10, fontWeight: 700, color: 'var(--text-3)', display: 'flex', gap: 12, boxShadow: 'var(--shadow)', flexWrap: 'wrap' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}><div style={{ width: 8, height: 8, borderRadius: 2, background: 'var(--crit)' }}/> Alert Process</div>
          {uniqueCategories.map(cat => (
             <div key={cat} style={{ display: 'flex', alignItems: 'center', gap: 4 }}><div style={{ width: 8, height: 8, borderRadius: 2, background: getCategoryColor(cat) }}/> <span style={{textTransform: 'capitalize'}}>{cat}</span></div>
          ))}
        </Panel>
        {(() => {
          const selectedNodeData = nodes.find(n => n.id === selectedNodeId)?.data as any
          if (!selectedNodeData || !selectedNodeData.raw) {
            return (
              <Panel position="top-right" style={{ background: 'var(--bg-2)', border: '1px dashed var(--border)', borderRadius: 8, padding: '12px 16px', color: 'var(--text-3)', fontSize: 11, fontWeight: 600 }}>
                Click any node for details
              </Panel>
            )
          }
          const r = selectedNodeData.raw
          
          return (
            <Panel position="top-right" style={{ background: 'var(--bg)', border: '1px solid var(--border)', borderRadius: 8, padding: 16, width: 320, boxShadow: 'var(--shadow-lg)', display: 'flex', flexDirection: 'column', gap: 12, zIndex: 50 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, flex: 1, overflow: 'hidden' }}>
                  {getCategoryIcon(selectedNodeData.category, 16, getCategoryColor(selectedNodeData.category))}
                  <div style={{ flex: 1, overflow: 'hidden' }}>
                    <div style={{ fontSize: 13, fontWeight: 700, color: 'var(--text)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{selectedNodeData.label}</div>
                    {r.__ts || r.UtcTime ? <div style={{ fontSize: 11, color: 'var(--text-3)', marginTop: 2 }}>{new Date(r.__ts || r.UtcTime).toLocaleString()}</div> : null}
                  </div>
                </div>
                <CopyButton text={JSON.stringify(r, null, 2)} size={14} />
              </div>
              
              {selectedNodeData.category === 'root' && (
                <>
                  <div>
                    <div style={{ fontSize: 10, fontWeight: 600, color: 'var(--text-3)', textTransform: 'uppercase', marginBottom: 4 }}>Role</div>
                    <div style={{ fontSize: 11, color: 'var(--crit)', fontWeight: 700 }}>Source Alert Process</div>
                  </div>
                  <div>
                    <div style={{ fontSize: 10, fontWeight: 600, color: 'var(--text-3)', textTransform: 'uppercase', marginBottom: 4, display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                      Process GUID
                    </div>
                    <div style={{ fontSize: 10, color: 'var(--text-3)', fontFamily: "'Courier New', monospace" }}>{r.guid || 'N/A'}</div>
                  </div>
                </>
              )}
              
              {selectedNodeData.category === 'file' && (
                <>
                  <div>
                    <div style={{ fontSize: 10, fontWeight: 600, color: 'var(--text-3)', textTransform: 'uppercase', marginBottom: 4, display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                      Target Filename
                    </div>
                    <div style={{ fontSize: 11, color: 'var(--text-2)', wordBreak: 'break-all' }}>{r.TargetFilename || 'N/A'}</div>
                  </div>
                </>
              )}

              {selectedNodeData.category === 'registry' && (
                <>
                  <div>
                    <div style={{ fontSize: 10, fontWeight: 600, color: 'var(--text-3)', textTransform: 'uppercase', marginBottom: 4, display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                      Target Object
                    </div>
                    <div style={{ fontSize: 11, color: 'var(--text-2)', wordBreak: 'break-all' }}>{r.TargetObject || 'N/A'}</div>
                  </div>
                  <div>
                    <div style={{ fontSize: 10, fontWeight: 600, color: 'var(--text-3)', textTransform: 'uppercase', marginBottom: 4 }}>Details</div>
                    <div style={{ fontSize: 11, color: 'var(--text-2)', fontFamily: "'Courier New', monospace", background: 'var(--bg-2)', padding: '6px 8px', borderRadius: 4, border: '1px solid var(--border-2)', wordBreak: 'break-all' }}>{r.Details || 'N/A'}</div>
                  </div>
                </>
              )}

              {selectedNodeData.category === 'network' && (
                <>
                  <div style={{ display: 'flex', gap: 12 }}>
                    <div style={{ flex: 1 }}>
                      <div style={{ fontSize: 10, fontWeight: 600, color: 'var(--text-3)', textTransform: 'uppercase', marginBottom: 4 }}>Source IP</div>
                      <div style={{ fontSize: 11, color: 'var(--text-2)', wordBreak: 'break-all' }}>{r.SourceIp || 'N/A'} : {r.SourcePort || ''}</div>
                    </div>
                    <div style={{ flex: 1 }}>
                      <div style={{ fontSize: 10, fontWeight: 600, color: 'var(--text-3)', textTransform: 'uppercase', marginBottom: 4 }}>Destination IP</div>
                      <div style={{ fontSize: 11, color: 'var(--text-2)', wordBreak: 'break-all' }}>{r.DestinationIp || 'N/A'} : {r.DestinationPort || ''}</div>
                    </div>
                  </div>
                </>
              )}

              {/* Dynamic Fallback for unknown categories */}
              {selectedNodeData.category !== 'file' && selectedNodeData.category !== 'registry' && selectedNodeData.category !== 'network' && selectedNodeData.category !== 'root' && (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                  {Object.entries(r).filter(([k]) => !k.startsWith('_')).map(([k, v]) => (
                    <div key={k}>
                      <div style={{ fontSize: 10, fontWeight: 600, color: 'var(--text-3)', textTransform: 'uppercase', marginBottom: 4 }}>{k}</div>
                      <div style={{ fontSize: 11, color: 'var(--text-2)', wordBreak: 'break-all' }}>{String(v)}</div>
                    </div>
                  ))}
                </div>
              )}
            </Panel>
          )
        })()}
        <GraphCameraController selectedNodeId={selectedNodeId} nodes={nodes} />
      </ReactFlow>
    </div>
  )
}
