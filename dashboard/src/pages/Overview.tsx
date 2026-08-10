import React, { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  AlertTriangle,
  Database,
  Monitor,
  Search,
  ShieldCheck,
  Wifi,
  ChevronRight,
  Trash2,
  MonitorOff,
  Download,
} from 'lucide-react'
import { api, type Alert, type RegisteredEndpoint } from '../api/client'
import { useDashboard } from '../context/DashboardContext'
import AgentInstallModal from '../components/AgentInstallModal'
import { sevClass, sevLabel } from '../utils/severity'
import { formatTime } from '../utils/time'

function relativeTime(val: string | number | null | undefined): string {
  if (!val) return 'Never'
  let ts: number
  if (typeof val === 'number') {
    ts = val > 1e11 ? val : val * 1000
  } else if (typeof val === 'string' && /^\d+(\.\d+)?$/.test(val)) {
    const num = parseFloat(val)
    ts = num > 1e11 ? num : num * 1000
  } else {
    ts = new Date(val as string).getTime()
  }
  if (Number.isNaN(ts)) return 'Unknown'
  const diff = Date.now() - ts
  if (diff < 0) return 'Just now'
  const mins = Math.floor(diff / 60000)
  if (mins < 1) return 'Just now'
  if (mins < 60) return `${mins}m ago`
  if (mins < 1440) return `${Math.floor(mins / 60)}h ago`
  return `${Math.floor(mins / 1440)}d ago`
}

function isLive(iso: string | null): boolean {
  if (!iso) return false
  return Date.now() - new Date(iso).getTime() < 5 * 60 * 1000
}

export default function Overview({ onHostClick, user }: { onHostClick?: (hostId: string) => void, user?: any }) {
  const navigate = useNavigate()
  const { stats, health } = useDashboard()
  const [hosts, setHosts] = useState<RegisteredEndpoint[]>([])
  const [alerts, setAlerts] = useState<Alert[]>([])
  const [search, setSearch] = useState('')
  const [loading, setLoading] = useState(true)
  const [showInstall, setShowInstall] = useState(false)

  useEffect(() => {
    let cancelled = false
    const load = async () => {
      try {
        const [he, a] = await Promise.all([
          api.getHosts(),
          api.getAlerts({ limit: 4 }),  // fetch exactly 4 - we show 4
        ])
        if (!cancelled) {
          setHosts(he.hosts ?? [])
          setAlerts(a.alerts ?? [])
        }
      } catch (e) {
        console.error(e)
      } finally {
        if (!cancelled) setLoading(false)
      }
    }
    load()
    const t = setInterval(() => { if (!document.hidden) load() }, 15000)
    document.addEventListener('visibilitychange', () => { if (!document.hidden) load() })
    return () => {
      cancelled = true
      clearInterval(t)
    }
  }, [])

  const rc = stats?.row_counts ?? {}
  const totalAlerts = rc.alerts ?? 0
  const totalHosts = hosts.length
  const liveHosts = hosts.filter(h => isLive(h.last_seen)).length
  const filteredHosts = hosts.filter(h => {
    const q = search.trim().toLowerCase()
    if (!q) return true
    return (h.pc_name || h.host_id).toLowerCase().includes(q) || h.host_id.toLowerCase().includes(q)
  })

  const handleDeleteHost = async (hostId: string, e: React.MouseEvent) => {
    e.stopPropagation()
    if (!window.confirm(`Delete endpoint "${hostId}" and all its telemetry?`)) return
    try {
      await api.deleteHost(hostId)
      setHosts(prev => prev.filter(h => h.host_id !== hostId))
    } catch (err) {
      alert(`Failed to delete endpoint: ${err}`)
    }
  }

  const handlePurgeHost = async (hostId: string, e: React.MouseEvent) => {
    e.stopPropagation()
    if (!window.confirm(`Purge all telemetry and alerts for endpoint "${hostId}"? The agent will stay enrolled.`)) return
    try {
      await api.purgeHost(hostId)
      alert('Data purged successfully.')
      load()
    } catch (err) {
      alert(`Failed to purge endpoint data: ${err}`)
    }
  }

  const handleRevokeHost = async (hostId: string, e: React.MouseEvent) => {
    e.stopPropagation()
    if (!window.confirm(`Revoke endpoint "${hostId}"? It will go offline and be blocked from sending logs.`)) return
    try {
      await api.revokeHost(hostId)
      alert('Agent revoked successfully.')
    } catch (err) {
      alert(`Failed to revoke agent: ${err}`)
    }
  }

    const severityCounts = stats?.severity_counts ?? { crit: 0, high: 0, med: 0, low: 0 }
    const dynamicMix = stats?.dynamic_mix ?? []

  if (loading) {
    return (
      <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
        <div className="spinner" />
      </div>
    )
  }

  return (
    <div style={{ flex: 1, overflow: 'auto', padding: 24 }}>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>

        {/* Header Card */}
        <div className="card" style={{ padding: 18 }}>
          <div style={{ padding: '8px 14px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
              <ShieldCheck size={16} color="var(--accent)" />
              <span style={{ fontSize: 11, fontWeight: 700, letterSpacing: '1px', textTransform: 'uppercase', color: 'var(--text-3)' }}>
                Eyxa Control Plane
              </span>
            </div>
            <h1 style={{ fontSize: 24, fontWeight: 800, color: 'var(--text)', letterSpacing: '-0.5px' }}>
              Security Overview
            </h1>

          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, minmax(0, 1fr))', gap: 12, marginTop: 16 }}>
            <SummaryCard
              icon={AlertTriangle}
              label="Total Alerts"
              value={totalAlerts}
              tone="var(--crit)"
              detail={`${severityCounts.crit} critical, ${severityCounts.high} high, ${severityCounts.med} med`}
            />
            <SummaryCard
              icon={Monitor}
              label="Endpoints"
              value={`${liveHosts}/${totalHosts}`}
              tone="var(--accent)"
              detail={liveHosts > 0 ? `${liveHosts} host${liveHosts === 1 ? '' : 's'} live now` : 'No live hosts'}
            />
            <SummaryCard
              icon={Database}
              label="Pipeline Lag"
              value={health?.lag_seconds != null ? `${health.lag_seconds}s` : 'n/a'}
              tone="var(--info)"
              detail={health?.last_event ? `Last event ${relativeTime((health.last_event as any).received_at)}` : 'No events'}
            />
          </div>
        </div>

        {/* Health Warnings Banner */}
        {health?.warnings?.length ? (
          <div className="card" style={{ padding: 14, borderColor: 'rgba(234,179,8,0.35)', background: 'rgba(234,179,8,0.08)' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
              <AlertTriangle size={14} color="#eab308" />
              <span style={{ fontSize: 13, fontWeight: 700, color: 'var(--text)' }}>System Notices</span>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
              {health.warnings.map(w => (
                <span key={w} style={{ fontSize: 12, color: 'var(--text-2)' }}>{w}</span>
              ))}
            </div>
          </div>
        ) : null}

        {/* Managed Endpoints Table */}
        <div className="card" style={{ overflow: 'hidden' }}>
          <div style={{
            padding: '14px 18px',
            borderBottom: '1px solid var(--border)',
            display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12, flexWrap: 'wrap',
          }}>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <Monitor size={15} color="var(--accent)" />
                <span style={{ fontSize: 14, fontWeight: 700, color: 'var(--text)' }}>Managed Endpoints</span>
                <span style={{
                  background: 'var(--bg-3)', border: '1px solid var(--border)', borderRadius: 99,
                  padding: '1px 8px', fontSize: 11, color: 'var(--text-3)',
                }}>
                  {hosts.length}
                </span>
              </div>

            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
              <div style={{ position: 'relative' }}>
                <Search size={13} style={{ position: 'absolute', left: 10, top: '50%', transform: 'translateY(-50%)', color: 'var(--text-3)' }} />
                <input
                  placeholder="Search hosts..."
                  value={search}
                  onChange={e => setSearch(e.target.value)}
                  style={{ paddingLeft: 30, paddingRight: 12, paddingTop: 7, paddingBottom: 7, width: 230, fontSize: 13 }}
                />
              </div>
              <button
                onClick={() => setShowInstall(true)}
                style={{
                  display: 'flex', alignItems: 'center', gap: 6,
                  padding: '6px 12px', background: 'var(--bg-3)', color: 'var(--text-2)',
                  border: '1px solid var(--border)', borderRadius: 6, cursor: 'pointer', fontSize: 13, fontWeight: 600,
                  transition: 'all 0.15s ease'
                }}
                onMouseOver={e => { e.currentTarget.style.background = 'var(--bg-4)'; e.currentTarget.style.color = 'var(--text)' }}
                onMouseOut={e => { e.currentTarget.style.background = 'var(--bg-3)'; e.currentTarget.style.color = 'var(--text-2)' }}
              >
                <Download size={14} /> Add Endpoint
              </button>
            </div>
          </div>

          {filteredHosts.length === 0 ? (
            <div className="empty-state" style={{ padding: 64, display: 'flex', flexDirection: 'column', alignItems: 'center', textAlign: 'center' }}>
              <Monitor size={48} style={{ color: 'var(--text-3)', marginBottom: 16 }} />
              <h3 style={{ fontSize: 20, fontWeight: 700, color: 'var(--text)', marginBottom: 8 }}>
                {search ? 'No hosts match your search' : 'No endpoints connected yet'}
              </h3>
              <p style={{ color: 'var(--text-3)', fontSize: 14, marginBottom: 24, maxWidth: 400 }}>
                {search ? 'Try adjusting your search query.' : 'Deploy the Eyxa agent to your Windows machines to start collecting real-time Sysmon telemetry and detecting advanced threats.'}
              </p>
              {!search && (
                <button
                  onClick={() => setShowInstall(true)}
                  style={{
                    display: 'flex', alignItems: 'center', gap: 8,
                    padding: '10px 20px', background: 'var(--bg-3)', color: 'var(--text)',
                    border: '1px solid var(--border)', borderRadius: 8, cursor: 'pointer', fontSize: 14, fontWeight: 600,
                    transition: 'all 0.15s ease'
                  }}
                  onMouseOver={e => { e.currentTarget.style.background = 'var(--bg-4)'; e.currentTarget.style.transform = 'translateY(-2px)' }}
                  onMouseOut={e => { e.currentTarget.style.background = 'var(--bg-3)'; e.currentTarget.style.transform = 'translateY(0)' }}
                >
                  <Download size={16} /> Download Windows Agent
                </button>
              )}
            </div>
          ) : (
            <table>
              <thead>
                <tr>
                  <th style={{ width: 180 }}>Endpoint</th>
                  <th style={{ width: 120 }}>Status</th>
                  <th style={{ width: 140 }}>Machine ID</th>
                  <th style={{ width: 140 }}>Registered</th>
                  <th style={{ width: 140 }}>Last Seen</th>
                  <th style={{ width: 80, textAlign: 'right' }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {filteredHosts.map(host => {
                  const live = isLive(host.last_seen)
                  return (
                    <tr
                      key={host.host_id}
                      className="clickable"
                      onClick={() => navigate(`/hosts/${encodeURIComponent(host.host_id)}`)}
                      title="Open Endpoint Details"
                    >
                      <td>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                          <div style={{
                            width: 32, height: 32, background: 'var(--bg-3)', border: '1px solid var(--border)',
                            borderRadius: 6, display: 'flex', alignItems: 'center', justifyContent: 'center',
                            fontSize: 12, fontWeight: 700, color: 'var(--text-2)'
                          }}>
                            {(host.pc_name || host.host_id).slice(0, 2).toUpperCase()}
                          </div>
                          <div>
                            <div style={{ fontSize: 13, fontWeight: 700, color: 'var(--text)' }}>
                              {host.pc_name || host.host_id}
                            </div>
                            <div style={{ fontSize: 11, color: 'var(--text-3)', marginTop: 2 }}>
                              {host.pc_name ? 'Windows Agent' : 'Unknown OS'}
                            </div>
                          </div>
                        </div>
                      </td>
                      <td>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                          <div style={{
                            width: 8, height: 8, borderRadius: '50%',
                            background: live ? '#22C55E' : 'var(--text-3)',
                          }} />
                          <span style={{ fontSize: 12, color: live ? '#22C55E' : 'var(--text-3)', fontWeight: 600 }}>
                            {live ? 'Live' : 'Offline'}
                          </span>
                        </div>
                      </td>
                      <td>
                        <span style={{ fontFamily: 'monospace', fontSize: 12, color: 'var(--text-2)' }}>
                          {host.host_id.slice(0, 16)}...
                        </span>
                      </td>
                      <td>
                        <span style={{ fontSize: 12, color: 'var(--text-3)' }}>
                          {relativeTime(host.registered_at)}
                        </span>
                      </td>
                      <td>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 4, color: 'var(--text-3)', fontSize: 12 }}>
                          <Wifi size={11} />
                          {relativeTime(host.last_seen)}
                        </div>
                      </td>
                      <td>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 6, justifyContent: 'flex-end' }}>
                          <button
                            type="button"
                            title="Revoke endpoint"
                            style={{ background: 'transparent', border: 'none', cursor: 'pointer', color: 'var(--text-3)', padding: 4 }}
                            onClick={(e) => handleRevokeHost(host.host_id, e)}
                          >
                            <MonitorOff size={14} />
                          </button>
                          <button
                            type="button"
                            title="Purge data"
                            style={{ background: 'transparent', border: 'none', cursor: 'pointer', color: 'var(--text-3)', padding: 4 }}
                            onClick={(e) => handlePurgeHost(host.host_id, e)}
                          >
                            <Database size={14} />
                          </button>
                          <button
                            type="button"
                            title="Delete endpoint"
                            style={{ background: 'transparent', border: 'none', cursor: 'pointer', color: '#EF4444', padding: 4 }}
                            onClick={(e) => handleDeleteHost(host.host_id, e)}
                          >
                            <Trash2 size={14} />
                          </button>
                        </div>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          )}
        </div>

        {/* Telemetry & Recent Alerts */}
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
          <div className="card" style={{ padding: 16 }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12 }}>
              <div>
                <div style={{ fontSize: 14, fontWeight: 700, color: 'var(--text)' }}>Sensor Health & Visibility</div>
              </div>
              <Database size={15} color="var(--accent)" />
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, minmax(0, 1fr))', gap: 10, marginTop: 14, maxHeight: 180, overflowY: 'auto', paddingRight: 4 }}>
              {dynamicMix.length === 0 ? (
                <div style={{ gridColumn: '1 / -1', textAlign: 'center', padding: '20px 0', fontSize: 13, color: 'var(--text-3)' }}>
                  No telemetry ingested yet.
                </div>
              ) : (
                dynamicMix.map((item: any, i: number) => (
                  <MetricChip key={i} label={item.category} value={item.count} />
                ))
              )}
            </div>
          </div>

          <div className="card" style={{ padding: 16 }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12 }}>
              <div>
                <div style={{ fontSize: 14, fontWeight: 700, color: 'var(--text)' }}>Recent Alerts</div>
              </div>
              <AlertTriangle size={15} color="var(--crit)" />
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: 8, marginTop: 14 }}>
              {alerts.length === 0 ? (
                <div style={{ fontSize: 13, color: 'var(--text-3)', padding: '20px 0', textAlign: 'center' }}>
                  The system is monitoring real telemetry. Alerts appear here when a Sigma rule fires.
                </div>
              ) : (
                alerts.map(a => (
                  <div key={a.alert_id} style={{
                    padding: '8px 12px', background: 'var(--bg-3)', borderRadius: 6,
                    display: 'flex', alignItems: 'center', justifyContent: 'space-between'
                  }}>
                    <div>
                      <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--text)' }}>{a.rule_name}</div>
                      <div style={{ fontSize: 11, color: 'var(--text-3)' }}>{a.technique_id || 'N/A'} · {formatTime(a.created_at)}</div>
                    </div>
                    <span className={`badge badge-${sevClass(a.severity_score)}`}>
                      {sevLabel(a.severity_score)}
                    </span>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>

      </div>
      
      {user && (
        <AgentInstallModal 
          isOpen={showInstall} 
          onClose={() => setShowInstall(false)} 
          enrollToken={user.enrollToken || ''}
          serverIp={user.serverIp || ''} 
        />
      )}
    </div>
  )
}

function SummaryCard({ icon: Icon, label, value, tone, detail }: {
  icon: React.ComponentType<{ size?: number; color?: string }>
  label: string
  value: React.ReactNode
  tone: string
  detail: string
}) {
  return (
    <div className="card" style={{ padding: 16 }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8 }}>
        <span style={{ fontSize: 12, fontWeight: 700, color: 'var(--text-3)', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
          {label}
        </span>
        <Icon size={16} color={tone} />
      </div>
      <div style={{ fontSize: 24, fontWeight: 900, color: 'var(--text)', marginTop: 8 }}>
        {value}
      </div>
      <div style={{ fontSize: 11, color: 'var(--text-3)', marginTop: 4 }}>
        {detail}
      </div>
    </div>
  )
}

function MetricChip({ label, value }: { label: string; value: number }) {
  return (
    <div style={{
      padding: '10px 12px', background: 'var(--bg-3)', border: '1px solid var(--border)',
      borderRadius: 8, display: 'flex', flexDirection: 'column', gap: 2,
    }}>
      <span style={{ fontSize: 11, color: 'var(--text-3)', fontWeight: 600 }}>{label}</span>
      <span style={{ fontSize: 16, fontWeight: 800, color: 'var(--text)' }}>{value.toLocaleString()}</span>
    </div>
  )
}
