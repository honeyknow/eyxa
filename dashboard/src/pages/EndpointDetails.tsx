import { useEffect, useState, useMemo } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { Activity, Server, Cpu, HardDrive, Network, ChevronLeft } from 'lucide-react'
import { LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer, Legend } from 'recharts'
import { api, type RegisteredEndpoint, type HardwareInventory, type LiveStats } from '../api/client'
import CommandConsole from '../components/CommandConsole'
import Button from '../components/Button'

const formatBytes = (bytes: number) => {
  if (bytes === 0) return '0 B/s'
  const k = 1024
  const sizes = ['B/s', 'KB/s', 'MB/s', 'GB/s']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i]
}

export default function EndpointDetails() {
  const { hostId } = useParams<{ hostId: string }>()
  const navigate = useNavigate()
  const [host, setHost] = useState<RegisteredEndpoint | null>(null)
  const [statsHistory, setStatsHistory] = useState<(LiveStats & { time: string })[]>([])

  useEffect(() => {
    api.getHosts().then(res => {
      const h = res.hosts.find(x => x.host_id === hostId)
      if (h) setHost(h)
    }).catch(console.error)
  }, [hostId])

  useEffect(() => {
    if (!host) return
    const wsUrl = (window.location.protocol === 'https:' ? 'wss://' : 'ws://') + window.location.host + '/ws/dashboard'
    const ws = new WebSocket(wsUrl)
    
    ws.onmessage = (ev) => {
      try {
        const msg = JSON.parse(ev.data)
        if (msg.type === 'live_stats' && msg.host_id === host.agent_id.toString()) {
          const s = msg.stats as any // raw C payload
          const d = new Date()
          const timeLabel = `${d.getHours().toString().padStart(2, '0')}:${d.getMinutes().toString().padStart(2, '0')}:${d.getSeconds().toString().padStart(2, '0')}`
          
          const mapped: LiveStats = {
            cpu_usage_pct: Number((s.cpu_pct || 0).toFixed(1)),
            ram_usage_pct: s.mem_total_mb > 0 ? Number((((s.mem_total_mb - s.mem_free_mb) / s.mem_total_mb) * 100).toFixed(1)) : 0,
            disk_usage_pct: Number((s.disk_pct || 0).toFixed(1)),
            disk_read_kbps: 0,
            disk_write_kbps: 0,
            net_recv_kbps: s.net_bps || 0,
            net_sent_kbps: 0
          }
          
          setStatsHistory(prev => {
            const next = [...prev, { ...mapped, time: timeLabel }]
            if (next.length > 180) next.shift() // keep last 180 ticks (15 mins)
            return next
          })
        }
      } catch (e) {
        console.error('WebSocket parse error', e)
      }
    }

    return () => ws.close()
  }, [host])

  const inventory: HardwareInventory | null = useMemo(() => {
    if (!host?.inventory) return null
    try {
      return typeof host.inventory === 'string' ? JSON.parse(host.inventory) : host.inventory
    } catch {
      return null
    }
  }, [host?.inventory])

  if (!host) {
    return <div style={{ padding: 40, color: 'var(--text-3)' }}>Loading endpoint...</div>
  }

  return (
    <div style={{ flex: 1, padding: 24, overflowY: 'auto' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 16, marginBottom: 24 }}>
        <Button onClick={() => navigate('/')} variant="secondary" icon={<ChevronLeft size={16} />}>Back</Button>
        <div>
          <h1 style={{ fontSize: 24, fontWeight: 800, color: 'var(--text)' }}>{host.pc_name || host.host_id}</h1>
          <div style={{ fontSize: 13, color: 'var(--text-3)' }}>Endpoint Command & Control</div>
        </div>
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: 24, minHeight: 'calc(100vh - 180px)' }}>
        
        {/* Top Col: Inventory & Stats */}
        <div style={{ display: 'flex', gap: 24 }}>
          
          <div className="card" style={{ padding: 16, flex: 1 }}>
            <h3 style={{ fontSize: 14, fontWeight: 700, color: 'var(--text)', display: 'flex', alignItems: 'center', gap: 8, marginBottom: 12 }}>
              <Server size={14} color="var(--accent)" /> System Inventory
            </h3>
            {inventory ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 12, fontSize: 12 }}>
                <div><span style={{ color: 'var(--text-3)' }}>OS:</span> {inventory.os_build || 'Unknown'}</div>
                <div><span style={{ color: 'var(--text-3)' }}>CPU:</span> {inventory.cpu || 'Unknown'}</div>
                <div><span style={{ color: 'var(--text-3)' }}>RAM:</span> {Math.round((inventory.ram_mb || 0) / 1024)} GB</div>
                
                {inventory.gpus && inventory.gpus.length > 0 && (
                  <div>
                    <span style={{ color: 'var(--text-3)' }}>GPUs:</span>
                    {inventory.gpus.map((g, i) => <div key={i} style={{ paddingLeft: 8 }}>- {g}</div>)}
                  </div>
                )}
                
                {inventory.network && inventory.network.length > 0 && (
                  <div>
                    <span style={{ color: 'var(--text-3)' }}>Network:</span>
                    {inventory.network.map((n, i) => (
                      <div key={i} style={{ paddingLeft: 8 }}>- {n.name} <span style={{ color: 'var(--text-3)', fontSize: 11 }}>(MAC: {n.mac})</span></div>
                    ))}
                  </div>
                )}
                
                {inventory.storage && inventory.storage.length > 0 && (
                  <div>
                    <span style={{ color: 'var(--text-3)' }}>Storage:</span>
                    {inventory.storage.map((s, i) => (
                      <div key={i} style={{ paddingLeft: 8 }}>- Drive {s.drive} <span style={{ color: 'var(--text-3)', fontSize: 11 }}>(Serial: {s.serial.trim()})</span></div>
                    ))}
                  </div>
                )}
              </div>
            ) : (
              <div style={{ fontSize: 12, color: 'var(--text-3)', fontStyle: 'italic' }}>
                Inventory data not available. (Agent might need to reconnect)
              </div>
            )}
          </div>

          <div className="card" style={{ padding: 16, flex: 1 }}>
            <h3 style={{ fontSize: 14, fontWeight: 700, color: 'var(--text)', display: 'flex', alignItems: 'center', gap: 8, marginBottom: 12 }}>
              <Activity size={14} color="#22C55E" /> Live Performance
            </h3>
            
            <div style={{ height: 180, marginBottom: 16 }}>
              <div style={{ fontSize: 11, color: 'var(--text-3)', marginBottom: 4 }}>CPU & RAM Usage (%)</div>
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={statsHistory} margin={{ top: 24, right: 5, left: 5, bottom: 2 }}>
                  <XAxis dataKey="time" hide />
                  <YAxis domain={[0, 100]} hide />
                  <Tooltip 
                    contentStyle={{ background: '#18181b', border: '1px solid #3f3f46', borderRadius: 8, fontSize: 12 }} 
                    formatter={(value: number, name: string) => [name === 'Net' ? formatBytes(value) : `${value}%`, name]}
                  />
                  <Legend verticalAlign="top" align="right" iconSize={8} wrapperStyle={{ top: 0, right: 10, fontSize: 11, color: 'var(--text-3)' }} />
                  <Line type="monotone" dataKey="cpu_usage_pct" stroke="#3b82f6" strokeWidth={2} dot={false} isAnimationActive={false} name="CPU" />
                  <Line type="monotone" dataKey="ram_usage_pct" stroke="#eab308" strokeWidth={2} dot={false} isAnimationActive={false} name="RAM" />
                  <Line type="monotone" dataKey="disk_usage_pct" stroke="#ec4899" strokeWidth={2} dot={false} isAnimationActive={false} name="Disk" />
                  <Line type="monotone" dataKey="net_recv_kbps" stroke="#a8a29e" strokeWidth={2} dot={false} isAnimationActive={false} name="Net" hide />
                </LineChart>
              </ResponsiveContainer>
            </div>
            
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
               <div style={{ background: 'var(--bg-3)', padding: 12, borderRadius: 8, border: '1px solid var(--border)' }}>
                 <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 11, color: 'var(--text-3)', marginBottom: 4 }}><Cpu size={12} color="#3b82f6"/> CPU</div>
                 <div style={{ fontSize: 18, fontWeight: 800 }}>{(statsHistory[statsHistory.length-1]?.cpu_usage_pct || 0).toFixed(1)}%</div>
               </div>
               <div style={{ background: 'var(--bg-3)', padding: 12, borderRadius: 8, border: '1px solid var(--border)' }}>
                 <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 11, color: 'var(--text-3)', marginBottom: 4 }}><Server size={12} color="#eab308"/> RAM</div>
                 <div style={{ fontSize: 18, fontWeight: 800 }}>{(statsHistory[statsHistory.length-1]?.ram_usage_pct || 0).toFixed(1)}%</div>
               </div>
               <div style={{ background: 'var(--bg-3)', padding: 12, borderRadius: 8, border: '1px solid var(--border)' }}>
                 <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 11, color: 'var(--text-3)', marginBottom: 4 }}><HardDrive size={12} color="#ec4899"/> Disk</div>
                 <div style={{ fontSize: 18, fontWeight: 800 }}>{(statsHistory[statsHistory.length-1]?.disk_usage_pct || 0).toFixed(1)}%</div>
               </div>
               <div style={{ background: 'var(--bg-3)', padding: 12, borderRadius: 8, border: '1px solid var(--border)' }}>
                 <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 11, color: 'var(--text-3)', marginBottom: 4 }}><Network size={12} color="#a8a29e"/> Net</div>
                 <div style={{ fontSize: 18, fontWeight: 800 }}>{formatBytes(statsHistory[statsHistory.length-1]?.net_recv_kbps || 0)}</div>
               </div>
            </div>
          </div>

        </div>

        {/* Bottom Col: Remote Console */}
        <div style={{ flex: 1, minHeight: 400 }}>
          <CommandConsole agentId={host.agent_id} />
        </div>

      </div>
    </div>
  )
}
