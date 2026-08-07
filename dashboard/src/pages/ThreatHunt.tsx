import { useState, useCallback, useEffect, useRef } from 'react'
import { useParams } from 'react-router-dom'
import AlertQueue from '../components/AlertQueue'
import EvidenceDrawer from '../components/EvidenceDrawer'
import ProcessTree from '../components/ProcessTree'
import BlastRadius from '../components/BlastRadius'
import OmniscientAI from '../components/OmniscientAI'
import Button from '../components/Button'
import { api, type Alert, type TimelineEvent } from '../api/client'
import { Database, Activity, Clock, GitBranch, Radiation, Play } from 'lucide-react'

const EVENT_COLORS: Record<string, string> = {
  process: '#F97316',
  network: '#3B82F6',
  file: '#EAB308',
  registry: '#14B8A6',
  amsi: '#EC4899',
  alert: '#EF4444',
  auth: '#06B6D4',
  system: '#A855F7',
  default: 'var(--text-3)',
}

function eventColor(type: string): string {
  return EVENT_COLORS[type] ?? EVENT_COLORS.default
}

function formatTime(iso: string): string {
  try {
    return new Date(iso).toLocaleString('en-US', {
      month: 'short', day: 'numeric', hour12: true, hour: '2-digit', minute: '2-digit', second: '2-digit'
    })
  } catch { return iso }
}

export default function ThreatHunt() {
  const { hostId: urlHostId } = useParams<{ hostId?: string }>()

  const [selectedAlert, setSelectedAlert] = useState<Alert | null>(null)
  const [selectedProcessGuid, setSelectedProcessGuid] = useState<string | null>(null)
  const [activeTab, setActiveTab] = useState<'evidence' | 'timeline' | 'tree' | 'blast' | 'ai'>('evidence')
  const [timelineEvents, setTimelineEvents] = useState<TimelineEvent[]>([])
  const [loadingTimeline, setLoadingTimeline] = useState(false)
  const [loadingMoreOlder, setLoadingMoreOlder] = useState(false)
  const [loadingMoreNewer, setLoadingMoreNewer] = useState(false)
  const [hasMoreOlder, setHasMoreOlder] = useState(true)
  const [hasMoreNewer, setHasMoreNewer] = useState(true)
  const [expandedId, setExpandedId] = useState<string | null>(null)
  const [selectedTypes, setSelectedTypes] = useState<Set<string>>(new Set())
  const [shouldScroll, setShouldScroll] = useState(false)
  const scrollLockRef = useRef(false)
  const highlightedEventRef = useRef<HTMLDivElement>(null)
  const scrollContainerRef = useRef<HTMLDivElement>(null)

  const toggleType = useCallback((t: string) => {
    setSelectedTypes(prev => {
      const next = new Set(prev)
      if (next.has(t)) next.delete(t)
      else next.add(t)
      return next
    })
  }, [])

  const sortAsc = (events: TimelineEvent[]) => [...events].sort((a, b) => new Date(a.event_timestamp).getTime() - new Date(b.event_timestamp).getTime());

  // When navigated to /hunt/:hostId (from Overview host row click),
  // auto-load timeline for that host
  useEffect(() => {
    if (!urlHostId) return
    setActiveTab('timeline')
    setLoadingTimeline(true)
    api.getTimeline({ host_id: urlHostId, hours: 1 })
      .then(res => {
        let incoming = res.events || []
        const normalEvents = incoming.filter(e => e.event_type !== 'alert')
        if (normalEvents.length > 0) {
          const oldestNormal = normalEvents.reduce((min, e) => new Date(e.event_timestamp) < new Date(min.event_timestamp) ? e : min)
          const oldestTime = new Date(oldestNormal.event_timestamp).getTime()
          incoming = incoming.filter(e => e.event_type !== 'alert' || new Date(e.event_timestamp).getTime() >= oldestTime)
        }
        setTimelineEvents(sortAsc(incoming))
      })
      .catch(() => setTimelineEvents([]))
      .finally(() => setLoadingTimeline(false))
  }, [urlHostId])

  useEffect(() => {
    if (selectedAlert?.raw_event_ref) {
      setSelectedProcessGuid(selectedAlert.raw_event_ref)
    }
  }, [selectedAlert])

  const handleSelectAlert = useCallback(async (alert: Alert) => {
    setSelectedAlert(alert)
    if ((activeTab === 'tree' || activeTab === 'blast') && !alert.raw_event_ref) {
      setActiveTab('evidence')
    }
    if (alert.host_id) {
      setLoadingTimeline(true)
      setHasMoreOlder(true)
      setHasMoreNewer(true)
      setShouldScroll(true)
      api.getTimeline({ alert_id: Number(alert.alert_id), direction: 'initial', limit: 250 })
        .then(res => {
          setTimelineEvents(sortAsc(res.events || []))
        })
        .catch(console.error)
        .finally(() => setLoadingTimeline(false))
    }
  }, [activeTab])

  useEffect(() => {
    if (shouldScroll && !loadingTimeline && activeTab === 'timeline' && highlightedEventRef.current) {
      // Lock pagination to prevent onScroll from aborting the animation
      scrollLockRef.current = true
      // Delay to ensure the browser has fully painted 500+ DOM nodes
      const t = setTimeout(() => {
        highlightedEventRef.current?.scrollIntoView({ behavior: 'smooth', block: 'center' })
        setShouldScroll(false)
        // Unlock pagination after the smooth scroll animation completes
        setTimeout(() => { scrollLockRef.current = false }, 800)
      }, 150)
      return () => clearTimeout(t)
    }
  }, [shouldScroll, loadingTimeline, activeTab, timelineEvents])

  const handleTimelineScroll = useCallback((e: React.UIEvent<HTMLDivElement>) => {
    if (scrollLockRef.current) return; // Prevent programmatic jumps from triggering pagination
    const target = e.currentTarget;
    if (loadingMoreOlder || loadingMoreNewer || timelineEvents.length === 0) return;

    // We strictly maintain timelineEvents in ASC order (oldest at index 0, newest at end).
    const isNearTop = target.scrollTop <= 150;
    const isNearBottom = target.scrollHeight - target.scrollTop - target.clientHeight <= 150;

    if (isNearTop && hasMoreOlder && !loadingMoreOlder) {
      setLoadingMoreOlder(true);
      const oldestEvent = timelineEvents[0];
      api.getTimeline({ host_id: selectedAlert?.host_id || urlHostId, cursor: oldestEvent.event_timestamp, direction: 'older', limit: 100 })
        .then(res => {
          if (res.events && res.events.length > 0) {
            setTimelineEvents(prev => sortAsc([...prev, ...res.events]));
            setTimeout(() => { target.scrollTop = 200; }, 0);
          } else {
            setHasMoreOlder(false);
          }
        })
        .catch(console.error)
        .finally(() => setLoadingMoreOlder(false));
    }

    if (isNearBottom && hasMoreNewer && !loadingMoreNewer) {
      setLoadingMoreNewer(true);
      const newestEvent = timelineEvents[timelineEvents.length - 1];
      api.getTimeline({ host_id: selectedAlert?.host_id || urlHostId, cursor: newestEvent.event_timestamp, direction: 'newer', limit: 100 })
        .then(res => {
          if (res.events && res.events.length > 0) {
            setTimelineEvents(prev => sortAsc([...prev, ...res.events]));
          } else {
            setHasMoreNewer(false);
          }
        })
        .catch(console.error)
        .finally(() => setLoadingMoreNewer(false));
    }
  }, [loadingMoreOlder, loadingMoreNewer, timelineEvents, hasMoreOlder, hasMoreNewer, selectedAlert, urlHostId]);

  return (
    <div style={{ flex: 1, display: 'flex', overflow: 'hidden', padding: 16, gap: 16 }}>

      {/* Alert Queue Sidebar */}
      <div style={{
        width: 340, flexShrink: 0, display: 'flex', flexDirection: 'column',
        background: 'var(--bg-2)', borderRadius: 12, border: '1px solid var(--border)',
        overflow: 'hidden', boxShadow: 'var(--shadow)',
      }}>
        <AlertQueue selectedId={selectedAlert?.alert_id ?? null} onSelect={handleSelectAlert} />
      </div>

      {/* Main View */}
      <div style={{
        flex: 1, overflow: 'hidden', display: 'flex', flexDirection: 'column',
        background: 'var(--bg-2)', borderRadius: 12, border: '1px solid var(--border)',
        boxShadow: 'var(--shadow)',
      }}>
        {/* Tab bar */}
        <div style={{
          display: 'flex', gap: 4, padding: '8px 12px',
          borderBottom: '1px solid var(--border)', background: 'var(--bg)', flexShrink: 0,
        }}>
          <Button variant="custom" customColor="var(--info)"
            onClick={() => setActiveTab('evidence')} active={activeTab === 'evidence'}
            icon={<Database size={12} />}
          >Evidence</Button>

          <Button variant="custom" customColor="#22C55E"
            onClick={() => setActiveTab('timeline')} active={activeTab === 'timeline'}
            icon={<Clock size={12} />}
          >Timeline</Button>

          <Button variant="custom" customColor="var(--low)"
            onClick={() => setActiveTab('tree')}
            disabled={!selectedAlert?.raw_event_ref}
            active={activeTab === 'tree'}
            icon={<GitBranch size={12} />}
          >Process Tree</Button>

          <Button variant="custom" customColor="var(--crit)"
            onClick={() => setActiveTab('blast')}
            disabled={!selectedAlert?.raw_event_ref}
            active={activeTab === 'blast'}
            icon={<Radiation size={12} />}
          >Blast Radius</Button>

          <Button variant="custom" customColor="#FFFFFF"
            onClick={() => setActiveTab('ai')}
            disabled={!selectedAlert}
            active={activeTab === 'ai'}
            className={selectedAlert ? "ai-btn-animated" : ""}
            icon={<Play size={12} fill="currentColor" />}
          >Omniscient AI</Button>

          <div style={{ flex: 1 }} />

          {selectedAlert && (
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 12, color: 'var(--text-3)' }}>
              Rule: <strong style={{ color: 'var(--text)', fontWeight: 600 }}>{selectedAlert.rule_name}</strong>
            </div>
          )}
        </div>

        {/* Content */}
        <div style={{ flex: 1, overflow: 'hidden', display: 'flex' }}>
          {!selectedAlert && activeTab !== 'timeline' ? (
            <div className="empty-state" style={{ flex: 1 }}>
              <Activity size={48} color="var(--border-2)" />
              <h3>No Alert Selected</h3>
              <p>Select an alert from the queue to investigate its evidence and telemetry.</p>
            </div>
          ) : activeTab === 'tree' ? (
            selectedAlert?.raw_event_ref
              ? <ProcessTree rootGuid={selectedAlert.raw_event_ref} alertGuids={[selectedAlert.raw_event_ref]} onNodeClick={setSelectedProcessGuid} />
              : <div className="empty-state" style={{ flex: 1, padding: 32 }}><GitBranch size={32} /><h3>No Process GUID</h3><p>This alert has no associated process GUID.</p></div>
          ) : activeTab === 'blast' ? (
            selectedProcessGuid || selectedAlert?.raw_event_ref
              ? <BlastRadius rootGuid={selectedProcessGuid || selectedAlert?.raw_event_ref} rootLabel={selectedAlert?.rule_name} />
              : <div className="empty-state" style={{ flex: 1, padding: 32 }}><Radiation size={32} /><h3>No Process GUID</h3><p>Blast radius requires a source process GUID.</p></div>
          ) : activeTab === 'ai' ? (
            selectedAlert ? <OmniscientAI alert={selectedAlert} /> : null
          ) : activeTab === 'evidence' ? (
            selectedAlert ? <EvidenceDrawer alert={selectedAlert} /> : null
          ) : (
            /* Timeline - styled like Firehose */
            <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
              <div style={{
                padding: '10px 16px', borderBottom: '1px solid var(--border)',
                display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                background: 'var(--bg)', flexShrink: 0,
              }}>
                <div>
                  <span style={{ fontSize: 13, fontWeight: 700, color: 'var(--text)' }}>
                    {selectedAlert ? "Context Timeline" : "Host Timeline"}
                  </span>
                  <span style={{ marginLeft: 8, fontSize: 11, color: 'var(--text-3)' }}>
                    {selectedAlert ? `±1 Hour of Alert · ${timelineEvents.length} events` : `Last 1 hour · ${timelineEvents.length} events`}
                  </span>
                </div>
                {(selectedAlert?.host_id || urlHostId) && (
                  <span style={{ fontSize: 11, color: 'var(--text-3)', fontFamily: 'monospace' }}>
                    {selectedAlert?.host_id ?? urlHostId}
                  </span>
                )}
              </div>

              <div style={{ padding: '8px 16px', display: 'flex', gap: 6, flexWrap: 'wrap', borderBottom: '1px solid var(--border)' }}>
                {Object.keys(EVENT_COLORS).filter(k => k !== 'default').map(t => {
                  const active = selectedTypes.has(t)
                  const color = eventColor(t)
                  return (
                    <button
                      key={t}
                      onClick={() => toggleType(t)}
                      style={{
                        padding: '4px 8px', borderRadius: 4, fontSize: 10, fontWeight: 700,
                        textTransform: 'uppercase', letterSpacing: '0.5px',
                        border: `1px solid ${active ? color : 'transparent'}`,
                        background: active ? `${color}18` : 'var(--bg-3)',
                        color: active ? color : 'var(--text-3)',
                        transition: 'all 0.15s',
                      }}
                    >
                      {t}
                    </button>
                  )
                })}
              </div>

              <div style={{ flex: 1, position: 'relative', display: 'flex', flexDirection: 'column', minHeight: 0 }}>
                <div className="scroll-y" style={{ flex: 1, padding: '8px 12px', paddingRight: '20px' }} onScroll={handleTimelineScroll} ref={scrollContainerRef}>
                  {loadingTimeline ? (
                    <div style={{ padding: 40, display: 'flex', justifyContent: 'center' }}>
                      <div className="spinner" />
                    </div>
                  ) : timelineEvents.length === 0 ? (
                    <div className="empty-state">
                      <Clock size={32} />
                      <h3>No events in last hour</h3>
                      <p>Select an alert with an enrolled host to view its event timeline.</p>
                    </div>
                  ) : (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                      {loadingMoreOlder && <div style={{ textAlign: 'center', padding: 10, fontSize: 11, color: 'var(--text-3)' }}>Loading older events...</div>}
                      {timelineEvents.filter(ev => selectedTypes.size === 0 || selectedTypes.has(ev.event_type)).map((ev, i) => {
                        const rowId = `${ev.id}-${i}`;
                        const isExpanded = expandedId === rowId;
                        return (
                          <div
                            key={rowId}
                            id={`event-${ev.id}`}
                            ref={ev.is_alert_trigger ? highlightedEventRef : null}
                            style={{
                              background: ev.is_alert_trigger ? 'var(--crit-bg)' : 'var(--bg-3)',
                              borderRadius: 6,
                              borderLeft: `3px solid ${ev.is_alert_trigger ? 'var(--crit)' : eventColor(ev.event_type)}`,
                              boxShadow: ev.is_alert_trigger ? '0 0 0 1px var(--crit)' : 'none',
                              transition: 'background 0.12s',
                              marginBottom: 4,
                            }}
                            className="row-item"
                          >
                            <div
                              onClick={() => setExpandedId(isExpanded ? null : rowId)}
                              style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '7px 10px', cursor: 'pointer' }}
                            >
                              {/* Type pill */}
                              <span style={{
                                fontSize: 9, fontWeight: 700, padding: '2px 6px', borderRadius: 4,
                                background: `${eventColor(ev.event_type)}18`,
                                color: eventColor(ev.event_type),
                                border: `1px solid ${eventColor(ev.event_type)}30`,
                                textTransform: 'uppercase', letterSpacing: '0.5px',
                                whiteSpace: 'nowrap', flexShrink: 0,
                              }}>
                                {ev.event_type}
                              </span>

                              {/* Label */}
                              <span style={{
                                flex: 1, fontSize: 12, color: 'var(--text-2)',
                                whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis',
                              }}>
                                {ev.label}
                              </span>

                              {/* Timestamp */}
                              <span style={{ fontSize: 10, color: 'var(--text-3)', flexShrink: 0, fontFamily: 'monospace' }}>
                                {formatTime(ev.event_timestamp)}
                              </span>
                            </div>
                            {isExpanded && ev.raw_json && (
                              <div style={{ padding: '0 10px 10px 10px' }}>
                                <pre style={{ margin: 0, padding: 10, borderRadius: 6, background: 'rgba(0,0,0,0.25)', color: 'var(--text-2)', fontSize: 10, overflowX: 'auto', whiteSpace: 'pre-wrap', border: '1px solid var(--border)' }}>
                                  {ev.raw_json}
                                </pre>
                              </div>
                            )}
                          </div>
                        )
                      })}
                      {loadingMoreNewer && <div style={{ textAlign: 'center', padding: 10, fontSize: 11, color: 'var(--text-3)' }}>Loading newer events...</div>}
                    </div>
                  )}
                </div>

                {/* Minimap Overlay */}
                <div style={{ position: 'absolute', right: 4, top: 12, bottom: 12, width: 4, pointerEvents: 'none', background: 'rgba(255,255,255,0.05)', borderRadius: 2 }}>
                  {timelineEvents.filter(ev => selectedTypes.size === 0 || selectedTypes.has(ev.event_type)).map((ev, i, arr) => {
                    if (!ev.is_alert_trigger && ev.event_type !== 'alert') return null;
                    return (
                      <div
                        key={`mm-${ev.id}`}
                        onClick={() => {
                          const el = document.getElementById(`event-${ev.id}`);
                          if (el) el.scrollIntoView({ behavior: 'smooth', block: 'center' });
                        }}
                        style={{
                          position: 'absolute', top: `${(i / Math.max(1, arr.length - 1)) * 100}%`, right: -4,
                          width: 12, height: 12, display: 'flex', alignItems: 'center', justifyContent: 'center',
                          pointerEvents: 'auto', cursor: 'pointer', transform: 'translateY(-50%)', zIndex: 10
                        }}
                      >
                        <div style={{ width: 4, height: 4, background: 'var(--crit)', borderRadius: 2 }} />
                      </div>
                    )
                  })}
                </div>
              </div>
            </div>
          )}
        </div>
      </div>

    </div>
  )
}
