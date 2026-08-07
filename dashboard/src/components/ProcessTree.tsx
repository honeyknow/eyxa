import { useCallback, useEffect, useState } from 'react'
import {
  ReactFlow, Background, Controls, Panel,
  useNodesState, useEdgesState, type Node, type Edge,
  Handle, Position, type NodeProps, useReactFlow,
} from '@xyflow/react'
import '@xyflow/react/dist/style.css'
import { api } from '../api/client'
import { GitBranch, Loader } from 'lucide-react'
import dagre from 'dagre'
import CopyButton from './CopyButton'

function basename(path: string) {
  return path.split(/[/\\]/).pop() ?? path
}

function ProcessNodeCard({ data }: NodeProps) {
  const { label, image, pid, user, isAlert, isSelected } = data as any
  return (
    <>
      <Handle type="target" position={Position.Top} isConnectable={false} style={{ opacity: 0 }} />
      <div className="hoverable-node" style={{
        background: 'var(--bg)',
        border: `1px solid ${isAlert ? 'var(--crit)' : isSelected ? '#3b82f6' : 'var(--border)'}`,
        borderLeft: `3px solid ${isAlert ? 'var(--crit)' : isSelected ? '#3b82f6' : 'var(--border-2)'}`,
        borderRadius: 6,
        padding: '8px 12px',
        minWidth: 180,
        maxWidth: 260,
        boxShadow: isAlert
          ? '0 0 0 3px rgba(204,0,0,0.10), 0 2px 8px rgba(0,0,0,0.10)'
          : isSelected
          ? '0 0 0 3px rgba(59, 130, 246, 0.15), 0 2px 8px rgba(0,0,0,0.10)'
          : '0 1px 4px rgba(0,0,0,0.08)',
      }}>
        <div style={{
          fontSize: 12, fontWeight: 700,
          color: isAlert ? 'var(--crit)' : 'var(--text)',
          whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis',
        }}>
          {label}
        </div>
        <div style={{
          fontSize: 10, color: 'var(--text-3)', marginTop: 2,
          fontFamily: "'Courier New', monospace",
          whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis',
        }}>
          {image}
        </div>
        <div style={{ display: 'flex', gap: 8, marginTop: 4 }}>
          {pid && <span style={{ fontSize: 10, color: 'var(--text-2)', background: 'var(--bg-3)', padding: '1px 5px', borderRadius: 3 }}>PID {pid}</span>}
          {user && <span style={{ fontSize: 10, color: 'var(--text-3)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{user}</span>}
        </div>
      </div>
      <Handle type="source" position={Position.Bottom} isConnectable={false} style={{ opacity: 0 }} />
    </>
  )
}

const NODE_TYPES = { process: ProcessNodeCard }

function buildLayout(tree: any, alertGuids: Set<string>, selectedGuid: string | null) {
  const dagreGraph = new dagre.graphlib.Graph()
  dagreGraph.setDefaultEdgeLabel(() => ({}))

  const NODE_W = 220
  const NODE_H = 70

  dagreGraph.setGraph({ rankdir: 'TB', nodesep: 40, ranksep: 90 })

  tree.nodes.forEach((n: any) => {
    dagreGraph.setNode(n.process_guid, { width: NODE_W, height: NODE_H })
  })

  tree.edges.forEach((e: any) => {
    dagreGraph.setEdge(e.source, e.target)
  })

  dagre.layout(dagreGraph)

  const nodes: Node[] = tree.nodes.map((n: any) => {
    const nodeWithPosition = dagreGraph.node(n.process_guid)
    return {
      id: n.process_guid,
      type: 'process',
      targetPosition: Position.Top,
      sourcePosition: Position.Bottom,
      position: {
        x: nodeWithPosition.x - NODE_W / 2,
        y: nodeWithPosition.y - NODE_H / 2,
      },
      data: {
        label:      basename(n.image || 'unknown'),
        image:      n.image || '',
        pid:        n.pid,
        user:       n.user_name || '',
        cmd:        n.command_line || '',
        guid:       n.process_guid || '',
        ts:         n.event_timestamp || '',
        isAlert:    alertGuids.has(n.process_guid),
        isSelected: n.process_guid === selectedGuid,
      },
      style: { cursor: 'pointer' },
    }
  })

  const edges: Edge[] = tree.edges.map((e: any) => ({
    id: `${e.source}-${e.target}`,
    source: e.source,
    target: e.target,
    style: { stroke: 'var(--border-2)', strokeWidth: 1.5 },
    animated: true,
  }))

  return { nodes, edges }
}

function GraphCameraController({ selectedNodeId, nodes }: { selectedNodeId: string | null, nodes: Node[] }) {
  const { setCenter, getZoom, fitView } = useReactFlow()
  const nodeIds = nodes.map(n => n.id).join(',')
  
  useEffect(() => {
    if (nodes.length === 0) return

    if (selectedNodeId) {
      const node = nodes.find(n => n.id === selectedNodeId)
      if (node) {
        // Shift camera center significantly to the right so the node is pushed to the left side
        const zoom = getZoom()
        const x = node.position.x + 110 + (250 / zoom)
        const y = node.position.y + 35
        setCenter(x, y, { zoom, duration: 500 })
      }
    } else {
      // If nothing is selected (or just deselected), fit the whole graph
      window.requestAnimationFrame(() => fitView({ padding: 0.2, duration: 500 }))
    }
  }, [selectedNodeId, nodeIds, setCenter, getZoom, fitView])
  
  return null
}

export default function ProcessTree({ rootGuid, alertGuids = [], onNodeClick }: { rootGuid?: string | null, alertGuids?: string[], onNodeClick?: (guid: string | null) => void }) {
  const [nodes, setNodes, onNodesChange] = useNodesState<Node>([])
  const [edges, setEdges, onEdgesChange] = useEdgesState<Edge>([])
  const [loading, setLoading]            = useState(false)
  const [selectedGuid, setSelectedGuid]  = useState<string | null>(null)

  const loadTree = useCallback(() => {
    if (!rootGuid) return
    setLoading(true)
    api.getProcessTree({ root_guid: rootGuid })
      .then((tree: any) => {
        const ag = new Set([...tree.alert_guids, ...alertGuids])
        const { nodes: n, edges: e } = buildLayout(tree, ag, rootGuid || null)
        setNodes(n)
        setEdges(e)
      })
      .catch(() => { setNodes([]); setEdges([]) })
      .finally(() => setLoading(false))
  }, [rootGuid, alertGuids, setNodes, setEdges])

  useEffect(() => {
    setSelectedGuid(null)
  }, [rootGuid])

  useEffect(() => {
    loadTree()
  }, [loadTree])

  const selectedNodeData = nodes.find(n => n.id === selectedGuid)?.data as any

  return (
    <div style={{ flex: 1, position: 'relative', background: 'var(--bg-2)', height: '100%' }}>
      {loading && (
        <div style={{
          position: 'absolute', top: 16, left: '50%', transform: 'translateX(-50%)',
          zIndex: 10, background: 'var(--bg)', padding: '6px 14px',
          borderRadius: 99, border: '1px solid var(--border)',
          display: 'flex', alignItems: 'center', gap: 6,
          fontSize: 12, color: 'var(--text-2)', boxShadow: 'var(--shadow)',
        }}>
          <Loader size={12} style={{ animation: 'spin 1s linear infinite' }} />
          Loading process tree…
        </div>
      )}
      {!loading && nodes.length === 0 && (
        <div style={{
          display: 'flex', flexDirection: 'column', alignItems: 'center',
          justifyContent: 'center', height: '100%', color: 'var(--text-3)', gap: 12,
        }}>
          <GitBranch size={32} strokeWidth={1} color="var(--border-2)" />
          <span style={{ fontSize: 13 }}>No process lineage found in database.</span>
        </div>
      )}
      <ReactFlow
        nodes={nodes}
        edges={edges}
        nodeTypes={NODE_TYPES}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        onPaneClick={() => {
          setSelectedGuid(null)
          setNodes(nds => nds.map(n => ({ ...n, data: { ...n.data, isSelected: false } })))
          onNodeClick?.(null)
        }}
        onNodeClick={(_, node) => {
          if (node.id === selectedGuid) {
            setSelectedGuid(null)
            setNodes(nds => nds.map(n => ({ ...n, data: { ...n.data, isSelected: false } })))
            onNodeClick?.(null)
          } else {
            setSelectedGuid(node.id)
            setNodes(nds => nds.map(n => ({ ...n, data: { ...n.data, isSelected: n.id === node.id } })))
            onNodeClick?.(node.id)
          }
        }}
        nodesDraggable={false}
        nodesConnectable={false}
        elementsSelectable={true}
        minZoom={0.2}
        maxZoom={2}
        proOptions={{ hideAttribution: true }}
        fitView
      >
        <Background variant="cross" color="var(--border)" gap={24} size={2} />
        <Controls showInteractive={true} />
        <Panel position="bottom-right" style={{ background: 'var(--bg)', padding: '8px 12px', borderRadius: 8, border: '1px solid var(--border)', fontSize: 10, fontWeight: 700, color: 'var(--text-3)', display: 'flex', flexWrap: 'wrap', gap: 12, boxShadow: 'var(--shadow)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}><div style={{ width: 8, height: 8, borderRadius: 2, background: 'var(--crit)' }}/> Alert Process</div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}><div style={{ width: 8, height: 8, borderRadius: 2, background: '#3b82f6' }}/> Selected</div>
        </Panel>
        {selectedNodeData ? (
          <Panel position="top-right" style={{ background: 'var(--bg)', border: '1px solid var(--border)', borderRadius: 8, padding: 16, width: 320, boxShadow: 'var(--shadow-lg)', display: 'flex', flexDirection: 'column', gap: 12 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
              <div>
                <div style={{ fontSize: 13, fontWeight: 700, color: 'var(--text)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{selectedNodeData.label}</div>
              <div style={{ fontSize: 11, color: 'var(--text-3)', marginTop: 2 }}>{new Date(selectedNodeData.ts).toLocaleString()}</div>
              </div>
              <CopyButton text={`Image: ${selectedNodeData.image || 'N/A'}\nCommandLine: ${selectedNodeData.cmd || 'N/A'}\nPID: ${selectedNodeData.pid || 'N/A'}\nUser: ${selectedNodeData.user || 'N/A'}\nGUID: ${selectedNodeData.guid || 'N/A'}`} size={14} />
            </div>
            
            <div>
              <div style={{ fontSize: 10, fontWeight: 600, color: 'var(--text-3)', textTransform: 'uppercase', marginBottom: 4, display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                Command Line
              </div>
              <div style={{ fontSize: 11, color: 'var(--text-2)', fontFamily: "'Courier New', monospace", background: 'var(--bg-2)', padding: '6px 8px', borderRadius: 4, border: '1px solid var(--border-2)', wordBreak: 'break-all' }}>
                {selectedNodeData.cmd || 'N/A'}
              </div>
            </div>

            <div>
              <div style={{ fontSize: 10, fontWeight: 600, color: 'var(--text-3)', textTransform: 'uppercase', marginBottom: 4, display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                Process Image
              </div>
              <div style={{ fontSize: 11, color: 'var(--text-2)', wordBreak: 'break-all' }}>{selectedNodeData.image || 'N/A'}</div>
            </div>

            <div style={{ display: 'flex', gap: 12 }}>
              <div>
                <div style={{ fontSize: 10, fontWeight: 600, color: 'var(--text-3)', textTransform: 'uppercase', marginBottom: 4 }}>PID</div>
                <div style={{ fontSize: 11, color: 'var(--text-2)' }}>{selectedNodeData.pid || 'N/A'}</div>
              </div>
              <div>
                <div style={{ fontSize: 10, fontWeight: 600, color: 'var(--text-3)', textTransform: 'uppercase', marginBottom: 4 }}>User</div>
                <div style={{ fontSize: 11, color: 'var(--text-2)' }}>{selectedNodeData.user || 'N/A'}</div>
              </div>
            </div>
            
            <div>
              <div style={{ fontSize: 10, fontWeight: 600, color: 'var(--text-3)', textTransform: 'uppercase', marginBottom: 4, display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                GUID
              </div>
              <div style={{ fontSize: 10, color: 'var(--text-3)', fontFamily: "'Courier New', monospace" }}>{selectedNodeData.guid || 'N/A'}</div>
            </div>
          </Panel>
        ) : (
          <Panel position="top-right" style={{ background: 'var(--bg-2)', border: '1px dashed var(--border)', borderRadius: 8, padding: '12px 16px', color: 'var(--text-3)', fontSize: 11, fontWeight: 600 }}>
            Click any node for details
          </Panel>
        )}
        <GraphCameraController selectedNodeId={selectedGuid} nodes={nodes} />
      </ReactFlow>
    </div>
  )
}
