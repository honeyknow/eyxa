import { useState, useEffect } from 'react'
import { useNavigate, useLocation } from 'react-router-dom'
import { Database, Download, ShieldAlert } from 'lucide-react'
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
  const [isGlitching, setGlitching] = useState(false)
  const { stats, health } = useDashboard()

  // Auto-glitch every 10 seconds
  useEffect(() => {
    const interval = setInterval(() => {
      setGlitching(true)
      setTimeout(() => setGlitching(false), 800) // Glitch lasts 800ms
    }, 10000)
    return () => clearInterval(interval)
  }, [])

  const rc = stats?.row_counts ?? {}
  const totalEvents = rc.events ?? 0
  const visibleNav = NAV.filter(n => !('adminOnly' in n) || isAdmin)

  return (
    <div className="topbar">
      <style>{`
        .glitch-wrapper {
          position: relative;
          display: flex;
          align-items: center;
          user-select: none;
          font-family: 'Inter', sans-serif;
          font-size: 20px;
          font-weight: 900;
          letter-spacing: 5px;
          cursor: pointer;
          color: #f8fafc;
        }

        .glitch-part {
          position: relative;
          display: inline-block;
        }

        .glitch-wrapper:hover .glitch-part::before,
        .glitch-wrapper:hover .glitch-part::after,
        .is-glitching .glitch-part::before,
        .is-glitching .glitch-part::after {
          content: attr(data-text);
          position: absolute;
          top: 0;
          left: 0;
          opacity: 0.9;
        }

        .glitch-wrapper:hover .glitch-part::before,
        .is-glitching .glitch-part::before {
          left: 2px;
          text-shadow: -2px 0 #00ffff;
          color: #f8fafc;
          background: var(--bg);
          clip-path: polygon(0 0, 100% 0, 100% 45%, 0 45%);
          animation: glitch-anim-1 2s infinite linear alternate-reverse;
        }

        .glitch-wrapper:hover .glitch-part::after,
        .is-glitching .glitch-part::after {
          left: -2px;
          text-shadow: -2px 0 #ef4444;
          color: #f8fafc;
          background: var(--bg);
          clip-path: polygon(0 80%, 100% 20%, 100% 100%, 0 100%);
          animation: glitch-anim-2 2.5s infinite linear alternate-reverse;
        }
        
        .eyxa-x {
          color: #ef4444;
          text-shadow: 0 0 16px rgba(239,68,68,0.8);
          animation: flicker 5s infinite;
        }

        .glitch-wrapper:hover .eyxa-x::before,
        .glitch-wrapper:hover .eyxa-x::after,
        .is-glitching .eyxa-x::before,
        .is-glitching .eyxa-x::after {
          color: #ef4444;
        }

        @keyframes glitch-anim-1 {
          0% { clip-path: polygon(0 12%, 100% 12%, 100% 15%, 0 15%); }
          20% { clip-path: polygon(0 45%, 100% 45%, 100% 50%, 0 50%); }
          40% { clip-path: polygon(0 20%, 100% 20%, 100% 30%, 0 30%); }
          60% { clip-path: polygon(0 60%, 100% 60%, 100% 65%, 0 65%); }
          80% { clip-path: polygon(0 80%, 100% 80%, 100% 85%, 0 85%); }
          100% { clip-path: polygon(0 5%, 100% 5%, 100% 10%, 0 10%); }
        }

        @keyframes glitch-anim-2 {
          0% { clip-path: polygon(0 82%, 100% 82%, 100% 85%, 0 85%); }
          20% { clip-path: polygon(0 5%, 100% 5%, 100% 10%, 0 10%); }
          40% { clip-path: polygon(0 60%, 100% 60%, 100% 70%, 0 70%); }
          60% { clip-path: polygon(0 40%, 100% 40%, 100% 45%, 0 45%); }
          80% { clip-path: polygon(0 20%, 100% 20%, 100% 25%, 0 25%); }
          100% { clip-path: polygon(0 95%, 100% 95%, 100% 100%, 0 100%); }
        }

        @keyframes flicker {
          0%, 19.999%, 22%, 62.999%, 64%, 64.999%, 70%, 100% {
            opacity: 1;
            text-shadow: 0 0 16px rgba(239,68,68,0.8);
          }
          20%, 21.999%, 63%, 63.999%, 65%, 69.999% {
            opacity: 0.5;
            text-shadow: none;
          }
        }
      `}</style>

      {/* Brand */}
      <div style={{
        display: 'flex', alignItems: 'center', gap: 8,
        paddingRight: 20, borderRight: '1px solid rgba(255,255,255,0.06)', marginRight: 4,
        flexShrink: 0,
      }}>
        <div className={`glitch-wrapper ${isGlitching ? 'is-glitching' : ''}`} onClick={() => navigate('/')}>
          <span className="glitch-part" data-text="EY">EY</span>
          <span className="glitch-part eyxa-x" data-text="X">X</span>
          <span className="glitch-part" data-text="A">A</span>
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
