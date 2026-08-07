/**
 * DashboardContext - single source of truth for stats and health.
 *
 * Both Topbar and Overview previously polled /stats and /health independently
 * every 10 seconds each, causing 4 duplicate requests per cycle.
 * This context polls once and distributes data to all consumers.
 */
import { createContext, useContext, useState, useEffect, type ReactNode } from 'react'
import { api, type Stats, type HealthStatus } from '../api/client'
import { usePolling } from '../hooks/usePolling'

interface DashboardContextValue {
  stats: Stats | null
  health: HealthStatus | null
  loading: boolean
  refetch: () => void
}

const DashboardContext = createContext<DashboardContextValue>({
  stats: null, health: null, loading: true, refetch: () => { }
})

async function fetchDashboard() {
  const [stats, health] = await Promise.all([api.getStats(), api.getHealth()])
  return { stats, health }
}

export function DashboardProvider({ children }: { children: ReactNode }) {
  const { data, loading, refetch } = usePolling(fetchDashboard, 10_000)
  
  // Track previous alert count to detect new alerts
  const [prevAlerts, setPrevAlerts] = useState<number>(0)
  
  useEffect(() => {
    if (!data?.stats) return
    const currentAlerts = data.stats.row_counts.alerts ?? 0
    
    // U1: Browser tab alert badge
    document.title = currentAlerts > 0 ? `(${currentAlerts}) Eyxa EDR` : 'Eyxa EDR'
    
    // U6: Alert sound notification
    if (currentAlerts > prevAlerts && prevAlerts > 0) {
      // Subtle beep sound (base64)
      const snd = new Audio("data:audio/wav;base64,UklGRmYAAABXQVZFZm10IBAAAAABAAEAQB8AAEAfAAABAAgAZGF0YUMAAAAAAAB+f35+fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+fg==")
      snd.volume = 0.5
      snd.play().catch(() => {})
    }
    
    setPrevAlerts(currentAlerts)
  }, [data?.stats])

  return (
    <DashboardContext.Provider value={{
      stats: data?.stats ?? null,
      health: data?.health ?? null,
      loading,
      refetch,
    }}>
      {children}
    </DashboardContext.Provider>
  )
}

export function useDashboard() {
  return useContext(DashboardContext)
}
