import { useEffect, useState, useRef } from 'react'

/**
 * Cancellable, visibility-aware polling hook.
 *
 * - Pauses automatically when the browser tab is hidden (Page Visibility API).
 * - Cancels the in-flight setState on unmount to prevent React warnings.
 * - Re-fetches immediately when the tab becomes visible again.
 *
 * Source: https://developer.mozilla.org/en-US/docs/Web/API/Page_Visibility_API
 */
export function usePolling<T>(
  fetcher: () => Promise<T>,
  intervalMs: number,
  deps: unknown[] = []
): { data: T | null; loading: boolean; error: Error | null; refetch: () => void } {
  const [data, setData]     = useState<T | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError]   = useState<Error | null>(null)
  const cancelledRef        = useRef(false)
  const fetcherRef          = useRef(fetcher)

  // Keep fetcherRef current without re-running the effect
  useEffect(() => { fetcherRef.current = fetcher })

  const refetch = () => {
    if (cancelledRef.current || document.hidden) return
    fetcherRef.current()
      .then(result => { if (!cancelledRef.current) { setData(result); setError(null) } })
      .catch(err  => { if (!cancelledRef.current) setError(err) })
      .finally(()  => { if (!cancelledRef.current) setLoading(false) })
  }

  useEffect(() => {
    cancelledRef.current = false
    setLoading(true)

    refetch()

    const t = setInterval(() => {
      if (!document.hidden) refetch()
    }, intervalMs)

    const onVisibility = () => { if (!document.hidden) refetch() }
    document.addEventListener('visibilitychange', onVisibility)

    return () => {
      cancelledRef.current = true
      clearInterval(t)
      document.removeEventListener('visibilitychange', onVisibility)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [intervalMs, ...deps])

  return { data, loading, error, refetch }
}
