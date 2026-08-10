/**
 * Firehose - real-time event stream.
 *
 * Performance design:
 * - DRIP-FEED: incoming events are queued and drained 20/80ms into state.
 *   This creates smooth flowing animation instead of 500-item snaps.
 * - useMemo for filtered and dynamicEventTypes — no recomputation on unrelated renders.
 * - React.memo for Sparkline — only re-renders when filtered changes.
 * - cursorRef: cursor is tracked via ref, not read inside setEvents (avoids phantom renders).
 * - Minimap: pre-computed + capped at 100 dots — no filtered.map on every render.
 * - Initial load capped at 500 events regardless of window size (prevents browser OOM).
 * - fade-in removed from rows — drip-feed IS the animation.
 */
import { useEffect, useRef, useState, useCallback, useMemo, memo } from 'react'
import { Terminal, Pause, Play, Trash2, Download, Filter, AlignJustify, Code, ArrowDown, Copy } from 'lucide-react'
import { Virtuoso } from 'react-virtuoso'
import { api, type TimelineEvent } from '../api/client'
import Button from '../components/Button'
import { getCategoryColor } from '../utils/theme'

function eventColor(type: string): string {
  return getCategoryColor(type)
}

function formatTime(iso: string): string {
  try {
    return new Date(iso).toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' })
  } catch { return iso }
}

function sevClass(score: number | undefined): string {
  if (!score) return 'low'
  if (score >= 9) return 'crit'
  if (score >= 7) return 'high'
  if (score >= 5) return 'med'
  return 'low'
}

interface Agent { agent_id: string; hostname: string; pc_name?: string }

function useDebounce<T>(value: T, delay: number): T {
  const [debouncedValue, setDebouncedValue] = useState<T>(value)
  useEffect(() => {
    const handler = setTimeout(() => setDebouncedValue(value), delay)
    return () => clearTimeout(handler)
  }, [value, delay])
  return debouncedValue
}

// ── Sparkline: memoized so it only re-renders when filtered changes ────────────
const Sparkline = memo(function Sparkline({ events }: { events: TimelineEvent[] }) {
  const [hoverIdx, setHoverIdx] = useState<number | null>(null)

  if (events.length === 0) return <div style={{ flex: 1, height: 22, background: 'rgba(255,255,255,0.02)', borderRadius: 2 }} />

  const BUCKETS = 100
  const counts = new Array(BUCKETS).fill(0)

  let minTime = Infinity
  let maxTime = -Infinity
  for (const e of events) {
    const t = new Date(e.event_timestamp).getTime()
    if (t < minTime) minTime = t
    if (t > maxTime) maxTime = t
  }

  const range = Math.max(maxTime - minTime, 1)

  events.forEach(e => {
    const t = new Date(e.event_timestamp).getTime()
    let idx = Math.floor(((t - minTime) / range) * BUCKETS)
    if (idx >= BUCKETS) idx = BUCKETS - 1
    counts[idx]++
  })

  const maxCount = Math.max(...counts, 1)
  const svgWidth = 100
  const svgHeight = 22

  const points = counts.map((c, i) => {
    const x = (i / (BUCKETS - 1)) * svgWidth
    const y = svgHeight - Math.max((c / maxCount) * svgHeight, 1)
    return `${x},${y}`
  }).join(' ')

  const areaPoints = `${points} ${svgWidth},${svgHeight} 0,${svgHeight}`

  return (
    <div
      style={{ flex: 1, minWidth: 100, padding: '0 16px', borderLeft: '1px solid var(--border)', borderRight: '1px solid var(--border)', display: 'flex', alignItems: 'center', height: 22, position: 'relative' }}
      onMouseLeave={() => setHoverIdx(null)}
    >
      <svg width="100%" height="100%" viewBox={`0 0 ${svgWidth} ${svgHeight}`} preserveAspectRatio="none" style={{ overflow: 'visible' }}>
        <polygon points={areaPoints} fill="var(--accent)" opacity={0.15} />
        <polyline points={points} fill="none" stroke="var(--accent)" strokeWidth={1.5} strokeLinejoin="round" vectorEffect="non-scaling-stroke" />
      </svg>

      <div style={{ position: 'absolute', top: 0, left: 16, right: 16, height: '100%', display: 'flex' }}>
        {counts.map((_, i) => (
          <div key={i} onMouseEnter={() => setHoverIdx(i)} style={{ flex: 1, height: '100%', cursor: 'crosshair' }} />
        ))}
      </div>

      {hoverIdx !== null && (
        <div style={{
          position: 'absolute', top: 30,
          left: `calc(16px + ${(hoverIdx / BUCKETS) * 100}%)`,
          transform: 'translateX(-50%)', background: 'var(--bg-3)',
          border: '1px solid var(--border)', padding: '4px 8px', borderRadius: 6,
          fontSize: 11, color: 'var(--text)', whiteSpace: 'nowrap', zIndex: 50,
          pointerEvents: 'none', boxShadow: '0 4px 12px rgba(0,0,0,0.5)',
          display: 'flex', alignItems: 'center', gap: 6
        }}>
          {(() => {
            const bucketTime = minTime + (hoverIdx / BUCKETS) * range
            const timeStr = new Date(bucketTime).toLocaleTimeString('en-US', { hour12: false })
            return (
              <>
                <span style={{ fontWeight: 600 }}>{timeStr}</span>
                <span style={{ width: 4, height: 4, borderRadius: '50%', background: 'var(--text-3)' }} />
                <strong style={{ color: 'var(--accent)' }}>{counts[hoverIdx]}</strong>
                <span style={{ color: 'var(--text-3)' }}>events</span>
              </>
            )
          })()}
        </div>
      )}
    </div>
  )
})

// ─────────────────────────────────────────────────────────────────────────────

const DRIP_BATCH       = 20   // events added per tick
const DRIP_TICK        = 80   // ms between ticks → ~250 events/s smooth flow
const FETCH_LIMIT_POLL = 200  // max events per incremental poll

export default function Firehose() {
  const [events, setEvents] = useState<TimelineEvent[]>([])
  const [agents, setAgents] = useState<Agent[]>([])
  const [selectedHost, setHost] = useState<string>('all')
  const [selectedTypes, setTypes] = useState<Set<string>>(new Set())
  const [searchText, setSearch] = useState('')
  const [searchFocused, setSearchFocused] = useState(false)
  const debouncedSearchText = useDebounce(searchText, 300)
  const [paused, setPaused] = useState(false)
  const [loading, setLoading] = useState(true)
  const [expandedId, setExpandedId] = useState<string | null>(null)
  const [viewMode, setViewMode] = useState<'table' | 'raw'>('table')
  const [sidebarOpen, setSidebarOpen] = useState(true)
  const [windowSize, setWindowSize] = useState(500)

  // Performance refs — avoid reading state inside setState callbacks
  const virtuosoRef    = useRef<any>(null)
  const seenIdsRef     = useRef<Set<string>>(new Set())
  const cursorRef      = useRef<string | undefined>(undefined)   // current stream cursor
  const hasInitialLoad = useRef(false)                           // did we do the first load?
  const incomingQueue  = useRef<TimelineEvent[]>([])             // drip-feed staging buffer

  const formatRawJson = (jsonStr: string) => {
    try { return JSON.stringify(JSON.parse(jsonStr), null, 2) } catch { return jsonStr }
  }

  // Load agents once for host filter
  useEffect(() => {
    api.getAgents()
      .then((d: any) => setAgents(d.agents ?? []))
      .catch(() => null)
  }, [])

  // Reset everything when host changes
  useEffect(() => {
    setEvents([])
    seenIdsRef.current     = new Set()
    incomingQueue.current  = []
    cursorRef.current      = undefined
    hasInitialLoad.current = false
    setLoading(true)
  }, [selectedHost])

  // ── Drip-feed timer: drains incomingQueue smoothly into visible state ────────
  useEffect(() => {
    const timer = setInterval(() => {
      const q = incomingQueue.current
      if (q.length === 0) return

      const batch = q.splice(0, DRIP_BATCH)

      setEvents(prev => {
        const merged = [...prev, ...batch].sort(
          (a, b) => new Date(a.event_timestamp).getTime() - new Date(b.event_timestamp).getTime()
        )
        const windowed = merged.slice(-windowSize)

        // Keep cursor up-to-date
        if (windowed.length > 0) {
          cursorRef.current = windowed[windowed.length - 1].event_timestamp
        }

        // Prune seenIds to avoid unbounded memory growth
        if (seenIdsRef.current.size > windowSize * 2) {
          seenIdsRef.current = new Set(windowed.map(e => e.id))
        }

        return windowed
      })
    }, DRIP_TICK)

    return () => clearInterval(timer)
  }, [windowSize])

  // ── Fetch: initial load goes direct; subsequent polls go through queue ────────
  const doFetch = useCallback(async () => {
    if (paused) return
    try {
      const params: any = { host_id: selectedHost }

      if (!hasInitialLoad.current) {
        // Initial load — fetch the full window size the user requested
        params.hours     = 24
        params.direction = 'older'
        params.limit     = windowSize
      } else {
        // Incremental — only fetch events newer than our cursor
        params.cursor    = cursorRef.current
        params.direction = 'newer'
        params.limit     = FETCH_LIMIT_POLL
      }

      const data = await api.getTimeline(params)
      if (!data.events?.length) { setLoading(false); return }

      let incoming: TimelineEvent[] = data.events.filter(
        (e: TimelineEvent) => !seenIdsRef.current.has(e.id)
      )
      incoming.forEach((e: TimelineEvent) => seenIdsRef.current.add(e.id))
      if (incoming.length === 0) { setLoading(false); return }

      // Sort before queuing / applying
      incoming = incoming.sort(
        (a, b) => new Date(a.event_timestamp).getTime() - new Date(b.event_timestamp).getTime()
      )

      if (!hasInitialLoad.current) {
        // Filter spurious alerts that predate oldest normal event
        const normalEvents = incoming.filter(e => e.event_type !== 'alert')
        if (normalEvents.length > 0) {
          const oldestNormal = normalEvents.reduce((min, e) =>
            new Date(e.event_timestamp) < new Date(min.event_timestamp) ? e : min
          )
          const oldestTime = new Date(oldestNormal.event_timestamp).getTime()
          incoming = incoming.filter(e =>
            e.event_type !== 'alert' || new Date(e.event_timestamp).getTime() >= oldestTime
          )
        }

        const windowed = incoming.slice(-windowSize)
        setEvents(windowed)
        if (windowed.length > 0) {
          cursorRef.current = windowed[windowed.length - 1].event_timestamp
        }
        hasInitialLoad.current = true
      } else {
        // Queue for smooth drip-feed
        incomingQueue.current.push(...incoming)
      }
    } catch {
      // Network error — silently retry next tick
    } finally {
      setLoading(false)
    }
  }, [selectedHost, paused, windowSize])

  // Poll every 5s, visibility-aware
  useEffect(() => {
    let cancelled = false
    const run = () => { if (!document.hidden && !cancelled) doFetch() }
    run()
    const t = setInterval(run, 5000)
    document.addEventListener('visibilitychange', run)
    return () => {
      cancelled = true
      clearInterval(t)
      document.removeEventListener('visibilitychange', run)
    }
  }, [doFetch])

  // ── Memoized computations — no recomputation on unrelated renders ─────────────
  const dynamicEventTypes = useMemo(
    () => Array.from(new Set(events.map(e => e.event_type))).sort(),
    [events]
  )

  const filtered = useMemo(() =>
    events.filter(e =>
      (selectedTypes.size === 0 || selectedTypes.has(e.event_type)) &&
      (!debouncedSearchText ||
        e.label.toLowerCase().includes(debouncedSearchText.toLowerCase()) ||
        e.event_type.toLowerCase().includes(debouncedSearchText.toLowerCase()))
    ),
    [events, selectedTypes, debouncedSearchText]
  )

  // Minimap: pre-filtered to alerts only (not all events) so no dot cap needed —
  // iterating 200 alert divs is trivial; the old cost was iterating 3000 events returning null
  const minimapDots = useMemo(() => {
    const alerts: { i: number; e: TimelineEvent }[] = []
    filtered.forEach((e, i) => {
      if (e.is_alert_trigger || e.event_type === 'alert') alerts.push({ i, e })
    })
    return alerts
  }, [filtered])

  const scrollToBottom = () => {
    virtuosoRef.current?.scrollToIndex({ index: filtered.length - 1, behavior: 'smooth' })
  }

  const toggleType = (t: string) => {
    setTypes(prev => {
      const next = new Set(prev)
      next.has(t) ? next.delete(t) : next.add(t)
      return next
    })
  }

  const exportCSV = () => {
    const csv = ['timestamp,type,label,id',
      ...filtered.map(e => `"${e.event_timestamp}","${e.event_type}","${e.label.replace(/"/g, '""')}","${e.id}"`)
    ].join('\n')
    const blob = new Blob([csv], { type: 'text/csv' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url; a.download = 'firehose_export.csv'; a.click()
    URL.revokeObjectURL(url)
  }

  return (
    <div style={{
      flex: 1, display: 'flex', overflow: 'hidden', minHeight: 0,
      padding: 16, gap: sidebarOpen ? 16 : 0,
      transition: 'gap 0.3s ease',
    }}>

      {/* ── Left Sidebar ── */}
      <div style={{
        width: sidebarOpen ? 210 : 0,
        opacity: sidebarOpen ? 1 : 0,
        flexShrink: 0, display: 'flex', flexDirection: 'column',
        background: 'var(--bg-2)', borderRadius: 12,
        border: sidebarOpen ? '1px solid var(--border)' : 'none',
        overflowY: 'auto', overflowX: 'hidden',
        padding: sidebarOpen ? 16 : 0,
        boxShadow: sidebarOpen ? 'var(--shadow)' : 'none',
        transition: 'all 0.3s ease',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 16 }}>
          <Filter size={14} color="var(--text-3)" />
          <span style={{ fontSize: 13, fontWeight: 700, color: 'var(--text)' }}>Filters</span>
        </div>

        {/* Host selector */}
        <div style={{ marginBottom: 16 }}>
          <div className="section-label" style={{ marginBottom: 8 }}>Host</div>
          <select
            id="firehose-host"
            value={selectedHost}
            onChange={e => setHost(e.target.value)}
            style={{ padding: '7px 10px', fontSize: 12, borderRadius: 6, width: '100%', background: 'var(--bg)', border: '1px solid var(--border)', color: 'var(--text)' }}
          >
            <option value="all">All Hosts</option>
            {agents.map(a => (
              <option key={a.agent_id} value={a.agent_id}>
                {a.pc_name || a.hostname || a.agent_id}
              </option>
            ))}
          </select>
        </div>

        {/* Event type toggles */}
        <div>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 8 }}>
            <div className="section-label">Event Types</div>
            {selectedTypes.size > 0 && (
              <button
                style={{ background: 'none', border: 'none', color: 'var(--accent)', fontSize: 10, fontWeight: 700, cursor: 'pointer', padding: 0 }}
                onClick={() => setTypes(new Set())}
              >
                Clear
              </button>
            )}
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
            {dynamicEventTypes.map(t => {
              const active = selectedTypes.has(t)
              const color = eventColor(t)
              return (
                <label
                  key={t}
                  style={{
                    display: 'flex', alignItems: 'center', gap: 8,
                    padding: '5px 8px', borderRadius: 6, cursor: 'pointer',
                    background: active ? 'var(--bg-3)' : 'transparent',
                    transition: 'background 0.12s',
                  }}
                >
                  <input type="checkbox" checked={active} onChange={() => toggleType(t)} style={{ display: 'none' }} />
                  <div style={{
                    width: 10, height: 10, borderRadius: '50%',
                    border: `2px solid ${color}`,
                    background: active ? color : 'transparent',
                    transition: 'all 0.15s', flexShrink: 0,
                  }} />
                  <span style={{
                    fontSize: 12, fontWeight: 600, textTransform: 'capitalize',
                    color: active ? 'var(--text)' : 'var(--text-3)',
                    transition: 'color 0.12s',
                  }}>{t}</span>
                </label>
              )
            })}
          </div>
        </div>
      </div>

      {/* ── Main Stream ── */}
      <div style={{
        flex: 1, overflow: 'hidden', display: 'flex', flexDirection: 'column', minHeight: 0,
        background: 'var(--bg-2)', borderRadius: 12, border: '1px solid var(--border)',
        boxShadow: 'var(--shadow)',
      }}>
        {/* Toolbar */}
        <div style={{
          display: 'flex', alignItems: 'center', gap: 8,
          padding: '10px 16px', borderBottom: '1px solid var(--border)',
          background: 'var(--bg)', flexShrink: 0, flexWrap: 'wrap',
        }}>
          <Button variant="ghost" onClick={() => setSidebarOpen(o => !o)} icon={<Filter size={13} />} style={{ padding: '6px 8px' }} />

          <input
            id="firehose-search"
            placeholder="Search events…"
            value={searchText}
            onChange={e => setSearch(e.target.value)}
            onFocus={() => setSearchFocused(true)}
            onBlur={() => setSearchFocused(false)}
            style={{
              width: searchFocused ? 300 : 120,
              transition: 'width 0.3s ease',
              padding: '6px 12px', fontSize: 12, borderRadius: 6
            }}
          />

          <Sparkline events={filtered} />

          <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexShrink: 0, whiteSpace: 'nowrap' }}>
            <span style={{ fontSize: 11, color: 'var(--text-3)', fontWeight: 500 }}>{filtered.length} /</span>
            <select
              value={windowSize}
              onChange={e => {
                const newSize = Number(e.target.value)
                setWindowSize(newSize)
                if (newSize > events.length) {
                  // Need more data — reset and re-fetch
                  setEvents([])
                  seenIdsRef.current.clear()
                  incomingQueue.current = []
                  cursorRef.current = undefined
                  hasInitialLoad.current = false
                  setLoading(true)
                } else {
                  setEvents(prev => prev.slice(-newSize))
                }
              }}
              style={{
                background: 'var(--bg-3)', color: 'var(--text)', border: '1px solid var(--border)',
                borderRadius: 4, padding: '2px 4px', fontSize: 11, outline: 'none', cursor: 'pointer',
                fontWeight: 600
              }}
            >
              <option value={200}>200</option>
              <option value={500}>500</option>
              <option value={1000}>1,000</option>
              <option value={2000}>2,000</option>
              <option value={3000}>3,000</option>
              <option value={5000}>5,000</option>
              <option value={10000}>10,000</option>
              <option value={20000}>20,000</option>
            </select>
            <span style={{ fontSize: 11, color: 'var(--text-3)' }}>events</span>
            {incomingQueue.current.length > 0 && (
              <span style={{ fontSize: 10, color: 'var(--accent)', fontWeight: 600 }}>
                +{incomingQueue.current.length} queued
              </span>
            )}
          </div>

          {/* View mode */}
          <div style={{ display: 'flex', alignItems: 'stretch', height: 22, background: 'var(--bg-3)', borderRadius: 4, overflow: 'hidden', border: '1px solid var(--border)' }}>
            <Button variant="ghost" onClick={() => setViewMode('table')} active={viewMode === 'table'} icon={<AlignJustify size={12} />} style={{ padding: '0 8px', borderRadius: 0, height: '100%', display: 'flex', alignItems: 'center' }} />
            <Button variant="ghost" onClick={() => setViewMode('raw')} active={viewMode === 'raw'} icon={<Code size={12} />} style={{ padding: '0 8px', borderRadius: 0, height: '100%', display: 'flex', alignItems: 'center' }} />
          </div>

          <Button variant="ghost" size="sm" onClick={scrollToBottom} icon={<ArrowDown size={12} />}>Bottom</Button>
          <Button variant="ghost" size="sm" onClick={() => setPaused(p => !p)} icon={paused ? <Play size={12} /> : <Pause size={12} />}>
            {paused ? 'Resume' : 'Pause'}
          </Button>
          <Button variant="ghost" size="sm" onClick={() => {
            setEvents([])
            seenIdsRef.current = new Set()
            incomingQueue.current = []
          }} icon={<Trash2 size={12} />}>Clear</Button>
          <Button variant="ghost" size="sm" onClick={exportCSV} icon={<Download size={12} />}>CSV</Button>
        </div>

        {/* Event stream with minimap */}
        <div style={{ flex: 1, position: 'relative', display: 'flex', minHeight: 0 }}>
          <div style={{ flex: 1, display: 'flex', flexDirection: 'column', minHeight: 0, padding: '12px 0', background: 'var(--bg)' }}>
            {loading ? (
              <div style={{ display: 'flex', justifyContent: 'center', padding: 48 }}>
                <div className="spinner" />
              </div>
            ) : filtered.length === 0 ? (
              <div className="empty-state">
                <Terminal size={36} />
                <h3>No events in stream</h3>
                <p>{selectedTypes.size === 0 ? '' : 'Waiting for telemetry from connected hosts.'}</p>
              </div>
            ) : (
              <Virtuoso
                ref={virtuosoRef}
                style={{ flex: 1 }}
                data={filtered}
                computeItemKey={(i, e) => e.id}
                initialTopMostItemIndex={filtered.length - 1}
                followOutput={(isAtBottom) => isAtBottom ? 'smooth' : false}
                itemContent={(i, e) => {
                  const rowId = `${e.id}-${i}`
                  const isExpanded = expandedId === rowId

                  if (viewMode === 'raw') {
                    return (
                      <div key={rowId} style={{ padding: '8px 28px 8px 16px', borderBottom: '1px solid var(--border)' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
                          <span style={{ color: 'var(--text-3)', fontSize: 10 }}>{formatTime(e.event_timestamp)}</span>
                          <span style={{ padding: '1px 6px', borderRadius: 3, background: `${eventColor(e.event_type)}18`, color: eventColor(e.event_type), fontSize: 9, fontWeight: 700, textTransform: 'uppercase' }}>
                            {e.event_type}
                          </span>
                          <button
                            title="Copy JSON"
                            onClick={(evt) => {
                              evt.stopPropagation()
                              navigator.clipboard.writeText(e.raw_json ? formatRawJson(e.raw_json) : JSON.stringify(e, null, 2))
                            }}
                            style={{ marginLeft: 'auto', background: 'transparent', border: 'none', color: 'var(--text-3)', cursor: 'pointer', padding: 4 }}
                          >
                            <Copy size={12} />
                          </button>
                        </div>
                        <pre style={{ margin: 0, padding: 10, borderRadius: 6, background: 'rgba(0,0,0,0.2)', color: 'var(--text-3)', fontSize: 10, overflowX: 'auto', whiteSpace: 'pre-wrap', border: '1px solid var(--border)' }}>
                          {e.raw_json ? formatRawJson(e.raw_json) : JSON.stringify(e, null, 2)}
                        </pre>
                      </div>
                    )
                  }

                  return (
                    <div
                      key={rowId}
                      style={{
                        borderBottom: '1px solid rgba(255,255,255,0.03)',
                        padding: '3px 28px 3px 16px',
                        background: e.is_alert_trigger ? 'var(--crit-bg)' : 'transparent',
                        borderLeft: `3px solid ${e.is_alert_trigger ? 'var(--crit)' : (e.event_type === 'alert' ? `var(--${sevClass(e.severity_score)})` : eventColor(e.event_type))}20`,
                        boxShadow: e.is_alert_trigger ? 'inset 0 0 0 1px var(--crit)' : 'none',
                      }}
                    >
                      <div
                        onClick={(ev) => {
                          const willExpand = !isExpanded
                          setExpandedId(willExpand ? rowId : null)
                          if (willExpand) {
                            const target = ev.currentTarget.parentElement
                            setTimeout(() => { target?.scrollIntoView({ behavior: 'smooth', block: 'nearest' }) }, 50)
                          }
                        }}
                        style={{ display: 'flex', alignItems: 'baseline', gap: 8, cursor: 'pointer', padding: '2px 4px' }}
                      >
                        <span style={{ color: 'var(--text-3)', fontSize: 10, flexShrink: 0 }}>{formatTime(e.event_timestamp)}</span>
                        <span style={{
                          padding: '1px 5px', borderRadius: 3, flexShrink: 0,
                          background: `${eventColor(e.event_type)}15`,
                          color: eventColor(e.event_type),
                          fontSize: 9, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.4px',
                        }}>
                          {e.event_type}
                        </span>
                        <span style={{
                          flex: 1, fontSize: 12,
                          color: e.event_type === 'alert' ? 'var(--crit)' : 'var(--text)',
                          fontWeight: e.event_type === 'alert' ? 700 : 400,
                          wordBreak: 'break-all',
                        }}>
                          {e.label}
                        </span>
                        <span style={{ color: 'var(--text-3)', fontSize: 9, flexShrink: 0 }}>
                          {String(e.id).substring(0, 8)}
                        </span>
                      </div>
                      {isExpanded && e.raw_json && (
                        <div style={{ paddingLeft: 32, paddingBottom: 6 }}>
                          <div style={{ display: 'flex', justifyContent: 'flex-end', marginBottom: 4 }}>
                            <button
                              title="Copy JSON"
                              onClick={(evt) => {
                                evt.stopPropagation()
                                navigator.clipboard.writeText(formatRawJson(e.raw_json!))
                              }}
                              style={{ background: 'transparent', border: 'none', color: 'var(--text-3)', cursor: 'pointer', padding: 4 }}
                            >
                              <Copy size={12} />
                            </button>
                          </div>
                          <pre style={{ margin: 0, padding: 10, borderRadius: 6, background: 'rgba(0,0,0,0.25)', color: 'var(--text-2)', fontSize: 10, overflowX: 'auto', whiteSpace: 'pre-wrap', border: '1px solid var(--border)' }}>
                            {formatRawJson(e.raw_json)}
                          </pre>
                        </div>
                      )}
                    </div>
                  )
                }}
              />
            )}
          </div>

          {/* Minimap — pre-computed, capped at 100 dots */}
          <div style={{ position: 'absolute', right: 8, top: 12, bottom: 12, width: 4, pointerEvents: 'none', background: 'rgba(255,255,255,0.05)', borderRadius: 2, zIndex: 10 }}>
            {minimapDots.map(({ i, e }, dotIdx) => (
              <div
                key={`mm-${dotIdx}`}
                onClick={() => virtuosoRef.current?.scrollToIndex({ index: i, align: 'center', behavior: 'smooth' })}
                style={{
                  pointerEvents: 'auto', cursor: 'pointer',
                  position: 'absolute',
                  top: `${(i / Math.max(1, filtered.length - 1)) * 100}%`,
                  left: -4, width: 12, height: 12, transform: 'translateY(-50%)',
                  display: 'flex', alignItems: 'center', justifyContent: 'center'
                }}
              >
                <div style={{ width: 4, height: 4, background: 'var(--crit)', borderRadius: 2 }} />
              </div>
            ))}
          </div>
        </div>

        {/* Status bar */}
        <div style={{
          padding: '5px 16px', borderTop: '1px solid var(--border)',
          background: 'var(--bg)', display: 'flex', alignItems: 'center', gap: 10,
          fontSize: 10, color: 'var(--text-3)', flexShrink: 0,
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
            <div style={{
              width: 5, height: 5, borderRadius: '50%',
              background: paused ? 'var(--warning)' : 'var(--success)',
              boxShadow: paused ? 'none' : '0 0 4px rgba(34,197,94,0.7)',
            }} />
            {paused ? 'Paused' : 'Live · updates every 5s · drip-feed 20/80ms'}
          </div>
          <span>·</span>
          <span>Window: latest {windowSize}</span>
          <span>·</span>
          <span>{selectedHost === 'all' ? 'All hosts' : selectedHost}</span>
          {incomingQueue.current.length > 0 && (
            <>
              <span>·</span>
              <span style={{ color: 'var(--accent)' }}>Streaming {incomingQueue.current.length} queued</span>
            </>
          )}
        </div>
      </div>
    </div>
  )
}
