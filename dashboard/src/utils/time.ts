/** Shared time-formatting utilities - single source of truth for all components. */

export function formatTime(iso: string | number | null | undefined): string {
  if (!iso) return 'Never'
  let ts: number
  if (typeof iso === 'number') {
    ts = iso > 1e11 ? iso : iso * 1000
  } else if (/^\d+(\.\d+)?$/.test(iso)) {
    const num = parseFloat(iso)
    ts = num > 1e11 ? num : num * 1000
  } else {
    ts = new Date(iso).getTime()
  }
  if (Number.isNaN(ts)) return 'Unknown'

  const d = new Date(ts)
  const pad = (n: number) => n.toString().padStart(2, '0')
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`
}

export function relTime(iso: string | number | null | undefined): string {
  if (!iso) return 'Never'
  let ts: number
  if (typeof iso === 'number') {
    ts = iso > 1e11 ? iso : iso * 1000
  } else if (/^\d+(\.\d+)?$/.test(iso)) {
    const num = parseFloat(iso)
    ts = num > 1e11 ? num : num * 1000
  } else {
    ts = new Date(iso).getTime()
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
