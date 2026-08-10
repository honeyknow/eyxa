/**
 * AlertQueue - live alert sidebar for Threat Hunt view.
 *
 * Investigation status and tags are fully backend-persisted:
 *  - Status (open/investigated) → POST /alerts/{id}/status
 *  - Tags (#falsepositive etc)  → POST /alerts/{id}/tags
 *  - GET /alerts returns both fields on every poll
 *
 * No localStorage is used for security-relevant state.
 * Polling uses the cancellable usePolling hook with Page Visibility awareness.
 */
import { useState, useCallback, useRef, useEffect } from 'react'
import { Shield, AlertTriangle, CheckCircle2, RotateCcw, Tag, X } from 'lucide-react'
import { api, type Alert } from '../api/client'
import { usePolling } from '../hooks/usePolling'
import { useToast } from '../context/ToastContext'
import { sevClass, sevLabel } from '../utils/severity'
import { formatTime, relTime } from '../utils/time'

interface Props {
  selectedId: string | null
  onSelect: (alert: Alert) => void
  limit?: number
}

const TAG_REC = ['#falsepositive', '#important', '#ignore', '#note']

export default function AlertQueue({ selectedId, onSelect, limit: propLimit }: Props) {
  const toast = useToast()
  const [tab, setTab] = useState<'open' | 'investigated'>('open')
  const [limit, setLimit] = useState(propLimit ?? 100)
  const [copiedId, setCopiedId] = useState<string | null>(null)

  // Tag input state
  const [taggingId, setTaggingId] = useState<string | null>(null)
  const [tagInput, setTagInput] = useState('')
  const tagInputRef = useRef<HTMLInputElement>(null)

  // In-flight action tracking to show per-alert loading states
  const [actionIds, setActionIds] = useState<Set<string>>(new Set())
  const markBusy = (id: string) => setActionIds(p => new Set([...p, id]))
  const markFree = (id: string) => setActionIds(p => { const n = new Set(p); n.delete(id); return n })

  // ── Polling ──────────────────────────────────────────────────────────────
  const fetcher = useCallback(() => api.getAlerts({ limit }), [limit])
  const { data, loading, refetch } = usePolling(fetcher, 5000, [limit])
  const alerts = data?.alerts ?? []

  // ── Derived lists ─────────────────────────────────────────────────────────
  // Use server-side status - no localStorage
  const openAlerts = alerts.filter(a => (a.status ?? 'open') === 'open')
  const investigatedAlerts = alerts.filter(a => a.status === 'investigated')
  const visibleAlerts = tab === 'open' ? openAlerts : investigatedAlerts

  // ── U4: Keyboard Shortcuts ────────────────────────────────────────────────
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      // Don't trigger if user is typing in an input
      if (e.target instanceof HTMLInputElement || e.target instanceof HTMLTextAreaElement) return

      if (e.key === 'Escape') {
        onSelect({} as Alert) // clear selection by passing invalid alert or handle upstream
      } else if (e.key === 'ArrowDown' || e.key === 'j') {
        e.preventDefault()
        const idx = visibleAlerts.findIndex(a => a.alert_id === selectedId)
        if (idx < visibleAlerts.length - 1) onSelect(visibleAlerts[idx + 1])
        else if (idx === -1 && visibleAlerts.length > 0) onSelect(visibleAlerts[0])
      } else if (e.key === 'ArrowUp' || e.key === 'k') {
        e.preventDefault()
        const idx = visibleAlerts.findIndex(a => a.alert_id === selectedId)
        if (idx > 0) onSelect(visibleAlerts[idx - 1])
      } else if (e.key === 'i' && selectedId) {
        e.preventDefault()
        const alert = visibleAlerts.find(a => a.alert_id === selectedId)
        if (alert && !actionIds.has(alert.alert_id)) {
          handleInvestigate(e as unknown as React.MouseEvent, alert)
        }
      }
    }
    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [visibleAlerts, selectedId, actionIds])

  // ── Actions ───────────────────────────────────────────────────────────────
  const handleInvestigate = async (e: React.MouseEvent, alert: Alert) => {
    e.stopPropagation()
    const newStatus = tab === 'open' ? 'investigated' : 'open'
    markBusy(alert.alert_id)
    try {
      await api.updateAlertStatus(alert.alert_id, newStatus)
      toast.success(
        newStatus === 'investigated' ? 'Alert investigated' : 'Alert reopened',
        alert.rule_name
      )
      refetch()
    } catch {
      toast.error('Action failed', 'Could not update alert status')
    } finally {
      markFree(alert.alert_id)
    }
  }

  const handleAddTag = async (alertId: string, tag: string) => {
    const clean = tag.trim().toLowerCase()
    if (!clean) return
    setTaggingId(null)
    setTagInput('')
    markBusy(alertId)
    try {
      await api.updateAlertTag(alertId, 'add', clean)
      refetch()
    } catch {
      toast.error('Tag failed', 'Could not add tag')
    } finally {
      markFree(alertId)
    }
  }

  const handleRemoveTag = async (alertId: string, tag: string) => {
    markBusy(alertId)
    try {
      await api.updateAlertTag(alertId, 'remove', tag)
      refetch()
    } catch {
      toast.error('Tag failed', 'Could not remove tag')
    } finally {
      markFree(alertId)
    }
  }

  // ── Render ────────────────────────────────────────────────────────────────
  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', background: 'var(--bg)', overflow: 'hidden' }}>

      {/* ── Tab Header ── */}
      <div style={{ flexShrink: 0, borderBottom: '1px solid var(--border)' }}>
        <div style={{ display: 'flex' }}>
          {(['open', 'investigated'] as const).map(t => {
            const count = t === 'open' ? openAlerts.length : investigatedAlerts.length
            const isActive = tab === t
            return (
              <button
                key={t}
                id={`alert-tab-${t}`}
                onClick={() => setTab(t)}
                style={{
                  flex: 1,
                  display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 6,
                  padding: '10px 0',
                  background: 'transparent', border: 'none',
                  borderBottom: isActive ? '2px solid var(--accent)' : '2px solid transparent',
                  cursor: 'pointer',
                  fontSize: 12, fontWeight: isActive ? 700 : 500,
                  color: isActive ? 'var(--text)' : 'var(--text-3)',
                  transition: 'all 0.15s',
                }}
              >
                {t === 'open'
                  ? <AlertTriangle size={12} color={isActive ? 'var(--crit)' : 'var(--text-3)'} />
                  : <CheckCircle2 size={12} color={isActive ? 'var(--success)' : 'var(--text-3)'} />
                }
                {t === 'open' ? 'Live Alerts' : 'Investigated'}
                <span style={{
                  background: t === 'open' && count > 0 ? 'var(--crit-bg)' : 'var(--bg-3)',
                  border: `1px solid ${t === 'open' && count > 0 ? 'rgba(255,34,51,0.2)' : 'var(--border)'}`,
                  color: t === 'open' && count > 0 ? 'var(--crit)' : 'var(--text-3)',
                  borderRadius: 99, padding: '0px 6px', fontSize: 10, fontWeight: 700,
                  minWidth: 20, textAlign: 'center',
                }}>
                  {count}
                </span>
              </button>
            )
          })}
        </div>
      </div>

      {/* ── Alert List ── */}
      <div className="scroll-y" style={{ flex: 1 }}>
        {loading && alerts.length === 0 ? (
          <div style={{ display: 'flex', justifyContent: 'center', padding: 40 }}>
            <div className="spinner" />
          </div>
        ) : visibleAlerts.length === 0 ? (
          <div className="empty-state">
            <Shield size={36} />
            <h3>{tab === 'open' ? 'No active alerts' : 'Nothing investigated yet'}</h3>
            <p style={{ fontSize: 12, color: 'var(--text-3)' }}>
              {tab === 'open'
                ? 'The system is monitoring real telemetry. Alerts appear here when a Sigma rule fires.'
                : ''}
            </p>
            {tab === 'open' && investigatedAlerts.length > 0 && (
              <button
                onClick={() => setTab('investigated')}
                style={{
                  marginTop: 8, padding: '5px 12px', fontSize: 11, fontWeight: 600,
                  color: 'var(--accent)', background: 'var(--accent-bg)',
                  border: '1px solid var(--accent-border)', borderRadius: 6, cursor: 'pointer',
                }}
              >
                View {investigatedAlerts.length} investigated →
              </button>
            )}
          </div>
        ) : (
          visibleAlerts.map(alert => {
            const sev = sevClass(alert.severity_score)
            const selected = alert.alert_id === selectedId
            const busy = actionIds.has(alert.alert_id)
            const tags = alert.tags ?? []

            return (
              <div
                key={alert.alert_id}
                id={`alert-${alert.alert_id}`}
                onClick={() => onSelect(alert)}
                className="row-item"
                style={{
                  padding: '12px 16px',
                  borderBottom: '1px solid var(--border)',
                  cursor: 'pointer',
                  background: selected ? 'var(--bg-3)' : 'transparent',
                  borderLeft: `3px solid var(--${sev})`,
                  opacity: alert.suppressed ? 0.5 : 1,
                  position: 'relative',
                }}
              >
                {/* Busy overlay */}
                {busy && (
                  <div style={{
                    position: 'absolute', inset: 0, zIndex: 2,
                    background: 'rgba(0,0,0,0.35)', display: 'flex',
                    alignItems: 'center', justifyContent: 'center', borderRadius: 2,
                  }}>
                    <div className="spinner-sm" style={{ color: 'var(--text-2)' }} />
                  </div>
                )}

                <div style={{ display: 'flex', alignItems: 'flex-start', gap: 8 }}>
                  <div style={{ paddingTop: 5, flexShrink: 0 }}>
                    <div className={`sev-dot sev-dot-${sev}`} />
                  </div>
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <p style={{ fontSize: 12, fontWeight: 600, color: 'var(--text)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', marginBottom: 3 }}>
                      {alert.rule_name}
                    </p>
                    {/* Badges & Relative Time Row */}
                    <div style={{ display: 'flex', alignItems: 'center', flexWrap: 'wrap', gap: 6, marginBottom: 6 }}>
                      <span className={`badge badge-${sev}`}>{sevLabel(alert.severity_score)}</span>
                      {alert.technique_id && <span className="tag">{alert.technique_id}</span>}
                      <span
                        onClick={e => {
                          e.stopPropagation()
                          navigator.clipboard.writeText(alert.alert_id)
                          setCopiedId(alert.alert_id)
                          setTimeout(() => setCopiedId(null), 2000)
                        }}
                        title={`Copy Alert ID: ${alert.alert_id}`}
                        style={{
                          fontSize: 10, fontWeight: 700, padding: '1px 6px', borderRadius: 4,
                          background: copiedId === alert.alert_id ? 'var(--info)' : 'rgba(255,255,255,0.15)',
                          color: '#fff',
                          border: '1px solid transparent', fontFamily: 'monospace', cursor: 'pointer',
                          transition: 'all 0.2s ease', whiteSpace: 'nowrap',
                        }}
                      >
                        {copiedId === alert.alert_id ? '✓ Copied' : `#${alert.alert_id}`}
                      </span>

                      {alert.suppressed && (
                        <span style={{ fontSize: 9, fontWeight: 700, padding: '1px 5px', borderRadius: 3, background: 'var(--bg-3)', color: 'var(--text-3)', border: '1px solid var(--border)', textTransform: 'uppercase' }}>
                          Suppressed
                        </span>
                      )}

                      {/* Backend tags */}
                      {tags.map(tag => (
                        <span
                          key={tag}
                          style={{
                            fontSize: 10, fontWeight: 600, padding: '1px 6px', borderRadius: 4,
                            background: tag === '#falsepositive' ? 'rgba(239,68,68,0.1)' : 'rgba(139,92,246,0.1)',
                            color: tag === '#falsepositive' ? 'var(--crit)' : '#a78bfa',
                            border: `1px solid ${tag === '#falsepositive' ? 'rgba(239,68,68,0.3)' : 'rgba(139,92,246,0.3)'}`,
                            display: 'inline-flex', alignItems: 'center', gap: 3,
                          }}
                        >
                          {tag}
                          <span
                            onClick={e => { e.stopPropagation(); handleRemoveTag(alert.alert_id, tag) }}
                            style={{ cursor: 'pointer', opacity: 0.6, lineHeight: 1 }}
                          >
                            <X size={9} />
                          </span>
                        </span>
                      ))}

                      {/* Relative Time (pushed to the right) */}
                      <span style={{ fontSize: 10, color: 'var(--text-3)', marginLeft: 'auto', flexShrink: 0 }}>
                        {relTime(alert.created_at)}
                      </span>
                    </div>

                    {/* Exact Time Row */}
                    <div style={{ display: 'flex', alignItems: 'center', marginBottom: 10 }}>
                      <span style={{ fontSize: 10, color: 'var(--text-4)', fontFamily: 'monospace', letterSpacing: '0.2px' }}>
                        {formatTime(alert.created_at)}
                      </span>
                    </div>

                    {/* Actions row */}
                    <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap' }}>
                      {/* Investigate / Reopen */}
                      <button
                        id={`btn-investigate-${alert.alert_id}`}
                        onClick={e => handleInvestigate(e, alert)}
                        disabled={busy}
                        style={{
                          display: 'inline-flex', alignItems: 'center', gap: 4,
                          padding: '3px 9px', fontSize: 10, fontWeight: 700,
                          borderRadius: 5, cursor: busy ? 'not-allowed' : 'pointer',
                          transition: 'all 0.15s',
                          background: tab === 'open' ? 'var(--success-bg)' : 'rgba(239,68,68,0.08)',
                          border: tab === 'open' ? '1px solid rgba(34,197,94,0.35)' : '1px solid rgba(239,68,68,0.25)',
                          color: tab === 'open' ? 'var(--success)' : 'var(--crit)',
                          opacity: busy ? 0.5 : 1,
                        }}
                      >
                        {busy
                          ? <div className="spinner-sm" />
                          : tab === 'open'
                            ? <><CheckCircle2 size={10} /> Mark Investigated</>
                            : <><RotateCcw size={10} /> Reopen</>
                        }
                      </button>

                      {/* Tag input / button */}
                      {taggingId === alert.alert_id ? (
                        <div style={{ position: 'relative' }} onClick={e => e.stopPropagation()}>
                          <input
                            ref={tagInputRef}
                            value={tagInput}
                            onChange={e => setTagInput(e.target.value)}
                            onKeyDown={e => {
                              if (e.key === 'Enter') { handleAddTag(alert.alert_id, tagInput) }
                              if (e.key === 'Escape') { setTaggingId(null); setTagInput('') }
                              if (e.key === ',') { e.preventDefault(); handleAddTag(alert.alert_id, tagInput) }
                            }}
                            onBlur={() => setTimeout(() => { setTaggingId(null); setTagInput('') }, 200)}
                            placeholder="#tag"
                            autoFocus
                            style={{
                              background: 'var(--bg-2)', color: 'var(--text)',
                              border: '1px solid var(--accent)', borderRadius: 4,
                              padding: '2px 6px', fontSize: 10, width: 110, outline: 'none',
                            }}
                          />
                          {/* Suggestions */}
                          {tagInput && TAG_REC.filter(t => t.includes(tagInput.toLowerCase())).length > 0 && (
                            <div style={{
                              position: 'absolute', top: '100%', left: 0, marginTop: 4,
                              background: 'var(--bg-3)', border: '1px solid var(--border)', borderRadius: 6,
                              padding: 4, zIndex: 99, display: 'flex', flexDirection: 'column', gap: 2, minWidth: 140,
                              boxShadow: 'var(--shadow-lg)',
                            }}>
                              {TAG_REC.filter(t => t.includes(tagInput.toLowerCase())).map(t => (
                                <div
                                  key={t}
                                  onMouseDown={e => { e.preventDefault(); handleAddTag(alert.alert_id, t) }}
                                  style={{ padding: '4px 8px', fontSize: 10, cursor: 'pointer', borderRadius: 4, color: 'var(--text-2)', transition: 'background 0.1s' }}
                                  onMouseEnter={e => (e.currentTarget as HTMLDivElement).style.background = 'var(--bg-4)'}
                                  onMouseLeave={e => (e.currentTarget as HTMLDivElement).style.background = 'transparent'}
                                >
                                  {t}
                                </div>
                              ))}
                            </div>
                          )}
                        </div>
                      ) : (
                        <button
                          id={`btn-tag-${alert.alert_id}`}
                          onClick={e => { e.stopPropagation(); setTaggingId(alert.alert_id); setTagInput('#') }}
                          style={{
                            display: 'inline-flex', alignItems: 'center', gap: 4,
                            padding: '3px 8px', fontSize: 10, fontWeight: 600,
                            background: 'transparent', border: '1px dashed var(--border)',
                            color: 'var(--text-3)', borderRadius: 5, cursor: 'pointer',
                            transition: 'all 0.15s',
                          }}
                        >
                          <Tag size={9} /> Tag
                        </button>
                      )}

                      {tab === 'investigated' && alert.investigated_by && (
                        <span style={{ marginLeft: 'auto', fontSize: 9, color: 'var(--text-3)' }}>
                          by {alert.investigated_by}
                        </span>
                      )}
                    </div>
                  </div>
                </div>
              </div>
            )
          })
        )}
      </div>

      {/* ── Footer: Limit selector ── */}
      <div style={{
        padding: '7px 14px', borderTop: '1px solid var(--border)',
        background: 'var(--bg-2)',
        display: 'flex', alignItems: 'center', gap: 4, flexShrink: 0,
      }}>
        <span style={{ fontSize: 10, color: 'var(--text-3)', marginRight: 2 }}>Show:</span>
        {[25, 50, 100, 200].map(val => (
          <button
            key={val}
            id={`alert-limit-${val}`}
            onClick={() => setLimit(val)}
            style={{
              background: limit === val ? 'var(--bg-4)' : 'transparent',
              color: limit === val ? 'var(--text)' : 'var(--text-3)',
              border: `1px solid ${limit === val ? 'var(--border-2)' : 'transparent'}`,
              borderRadius: 4, padding: '2px 7px', fontSize: 10,
              fontWeight: limit === val ? 700 : 500, cursor: 'pointer',
              transition: 'all 0.12s',
            }}
          >
            {val}
          </button>
        ))}
        {/* Loading indicator when refetching */}
        {loading && alerts.length > 0 && (
          <div className="spinner-sm" style={{ marginLeft: 'auto', color: 'var(--text-3)' }} />
        )}
      </div>
    </div>
  )
}
