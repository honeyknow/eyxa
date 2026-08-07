import { useState } from 'react'
import { useNavigate, useLocation } from 'react-router-dom'
import { Database, Download } from 'lucide-react'
import { useDashboard } from '../context/DashboardContext'
import AccountMenu from './AccountMenu'
import AgentInstallModal from './AgentInstallModal'

interface UserIdentity {
  email: string
  role: 'admin' | 'user'
  enrollToken?: string
}

interface Props {
  user?: UserIdentity | null
  onSignOut?: () => void
  isAdmin?: boolean
}

const NAV = [
  { path: '/',         label: 'Overview' },
  { path: '/hunt',     label: 'Threat Hunt' },
  { path: '/rules',    label: 'Rules Engine' },
  { path: '/firehose', label: 'Firehose' },
  { path: '/admin',    label: 'Admin', adminOnly: true },
] as const

function statusColor(status?: string): string {
  if (status === 'healthy')  return '#22C55E'
  if (status === 'degraded') return '#EAB308'
  return 'var(--text-3)'
}

function statusBorder(status?: string): string {
  if (status === 'healthy')  return 'rgba(34,197,94,0.35)'
  if (status === 'degraded') return 'rgba(234,179,8,0.35)'
  return 'rgba(255,255,255,0.08)'
}

export default function Topbar({ user, onSignOut, isAdmin }: Props) {
  const navigate  = useNavigate()
  const location  = useLocation()
  const [showInstall, setShowInstall] = useState(false)
  const { stats, health } = useDashboard()

  const rc = stats?.row_counts ?? {}
  const totalEvents = rc.events ?? 0
  const visibleNav = NAV.filter(n => !('adminOnly' in n) || isAdmin)

  return (
    <div className="topbar">
      {/* Brand */}
      <div style={{
        display: 'flex', alignItems: 'center', gap: 8,
        paddingRight: 20, borderRight: '1px solid rgba(255,255,255,0.06)', marginRight: 4,
        flexShrink: 0,
      }}>
        <div style={{ display: 'flex', alignItems: 'center', userSelect: 'none', fontStyle: 'italic', fontFamily: "'JetBrains Mono', monospace" }}>
          <span style={{ fontSize: 20, fontWeight: 900, letterSpacing: '6px', color: '#f8fafc' }}>
            EY
          </span>
          <span style={{ 
            fontSize: 20, 
            fontWeight: 900, 
            letterSpacing: '6px',
            color: '#ef4444', 
            textShadow: '0 0 16px rgba(239,68,68,0.8)'
          }}>
            X
          </span>
          <span style={{ fontSize: 20, fontWeight: 900, letterSpacing: '6px', color: '#f8fafc' }}>
            A
          </span>
        </div>
      </div>

      {/* Navigation */}
      <nav style={{ display: 'flex', alignItems: 'center', gap: 2, padding: '0 4px', flexShrink: 0 }}>
        {visibleNav.map(n => {
          // Match /hunt and /hunt/:hostId as same active tab
          const active = n.path === '/'
            ? location.pathname === '/'
            : location.pathname.startsWith(n.path)
          return (
            <button
              key={n.path}
              id={`nav-${n.label.toLowerCase().replace(/\s+/g, '-')}`}
              onClick={() => navigate(n.path)}
              style={{
                display: 'flex', alignItems: 'center',
                padding: '5px 11px',
                background: 'transparent',
                border: 'none',
                borderRadius: 6,
                cursor: 'pointer',
                fontSize: 12,
                fontWeight: active ? 700 : 500,
                whiteSpace: 'nowrap',
                flexShrink: 0,
                color: active ? '#fff' : 'var(--text-3)',
                position: 'relative',
                transition: 'all 0.15s ease',
              }}
              onMouseEnter={e => { if (!active) (e.currentTarget as HTMLElement).style.color = 'var(--text-2)' }}
              onMouseLeave={e => { if (!active) (e.currentTarget as HTMLElement).style.color = 'var(--text-3)' }}
            >
              {n.label}
              {active && (
                <div style={{
                  position: 'absolute', bottom: -1, left: 8, right: 8, height: 2,
                  background: '#ef4444',
                  boxShadow: '0 -1px 8px rgba(239,68,68,0.8)',
                  borderRadius: '2px 2px 0 0'
                }} />
              )}
            </button>
          )
        })}
      </nav>

      <div style={{ flex: 1 }} />

      {/* Right side: Health + Events + Account */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexShrink: 0 }}>
        {/* Health pill */}
        <div style={{
          display: 'flex', alignItems: 'center', gap: 5,
          padding: '3px 10px',
          background: 'transparent',
          border: `1px solid ${statusBorder(health?.status)}`,
          borderRadius: 99,
          whiteSpace: 'nowrap',
        }}>
          <div style={{
            width: 6, height: 6, borderRadius: '50%',
            background: statusColor(health?.status),
            boxShadow: health?.status === 'healthy' ? '0 0 5px rgba(34,197,94,0.7)' : 'none',
          }} />
          <span style={{ fontSize: 11, fontWeight: 700, color: statusColor(health?.status) }}>
            {(health?.status ?? 'Unknown').toUpperCase()}
          </span>
        </div>

        {/* Events count */}
        <div style={{
          display: 'flex', alignItems: 'center', gap: 5,
          padding: '3px 10px',
          background: 'rgba(239,68,68,0.08)',
          border: '1px solid rgba(239,68,68,0.3)',
          borderRadius: 99,
          whiteSpace: 'nowrap',
        }}>
          <Database size={11} color="#fca5a5" />
          <span style={{ fontSize: 11, color: '#fca5a5', fontWeight: 600 }}>
            {totalEvents.toLocaleString()} Events
          </span>
        </div>

        <div style={{ width: 1, height: 20, background: 'rgba(255,255,255,0.06)', flexShrink: 0 }} />

        <button
          onClick={() => setShowInstall(true)}
          style={{
            display: 'flex', alignItems: 'center', gap: 6,
            padding: '5px 12px',
            background: 'var(--bg-3)',
            color: 'var(--text-2)',
            border: '1px solid var(--border)',
            borderRadius: 6,
            cursor: 'pointer',
            fontSize: 12,
            fontWeight: 600,
            transition: 'all 0.15s ease',
          }}
          onMouseOver={e => { e.currentTarget.style.background = 'var(--bg-4)'; e.currentTarget.style.color = 'var(--text)' }}
          onMouseOut={e => { e.currentTarget.style.background = 'var(--bg-3)'; e.currentTarget.style.color = 'var(--text-2)' }}
        >
          <Download size={14} /> Download
        </button>

        {user && (
          <AgentInstallModal 
            isOpen={showInstall} 
            onClose={() => setShowInstall(false)} 
            enrollToken={user.enrollToken || ''}
            serverIp={user.serverIp || ''} 
          />
        )}

        {user && (
          <AccountMenu
            email={user.email}
            role={user.role}
            onSignOut={onSignOut}
          />
        )}
      </div>
    </div>
  )
}
