import React, { useState, useRef, useEffect } from 'react'
import { LogOut, ChevronDown, User, Trash2 } from 'lucide-react'
import { api } from '../api/client'

interface AccountMenuProps {
  email: string
  role: 'admin' | 'user'
  onSignOut?: () => void
}

export default function AccountMenu({ email, role, onSignOut }: AccountMenuProps) {
  const [open, setOpen] = useState(false)
  const [deleting, setDeleting] = useState(false)
  const [confirmDelete, setConfirmDelete] = useState(false)
  const ref = useRef<HTMLDivElement>(null)

  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) {
        setOpen(false)
        setConfirmDelete(false)
      }
    }
    document.addEventListener('mousedown', handler)
    return () => document.removeEventListener('mousedown', handler)
  }, [])

  const handleDeleteAccount = async () => {
    if (!confirmDelete) {
      setConfirmDelete(true)
      return
    }
    setDeleting(true)
    try {
      await api.deleteMyData()
      alert('Your account and all data have been permanently deleted.')
      if (onSignOut) onSignOut()
    } catch (e) {
      alert('Failed to delete account.')
    } finally {
      setDeleting(false)
      setConfirmDelete(false)
      setOpen(false)
    }
  }

  const rawPrefix = email.split('@')[0].replace(/[._-]/g, ' ')
  const displayName = rawPrefix.split(' ').map(w => w.charAt(0).toUpperCase() + w.slice(1)).join(' ')

  return (
    <div ref={ref} style={{ position: 'relative', userSelect: 'none' }}>
      <button
        onClick={() => { setOpen(o => !o); setConfirmDelete(false) }}
        style={{
          display: 'flex', alignItems: 'center', gap: 10,
          padding: '4px 8px', background: 'transparent', border: 'none',
          cursor: 'pointer', color: 'var(--text-1)',
        }}
      >
        <div style={{
          width: 32, height: 32, borderRadius: '50%',
          background: 'rgba(239, 68, 68, 0.2)', border: '1px solid rgba(239, 68, 68, 0.4)',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          flexShrink: 0,
        }}>
          <User size={16} color="#ef4444" />
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-start' }}>
          <span style={{ fontSize: 13, fontWeight: 600, color: '#fff' }}>
            {displayName}
          </span>
        </div>
        <ChevronDown size={14} color="var(--text-3)" style={{ transition: 'transform 0.15s', transform: open ? 'rotate(180deg)' : 'rotate(0deg)', marginLeft: 4 }} />
      </button>

      {open && (
        <div style={{
          position: 'absolute', top: 'calc(100% + 6px)', right: 0,
          minWidth: 220, background: 'var(--bg-2)', border: '1px solid var(--border)',
          borderRadius: 10, boxShadow: '0 8px 32px rgba(0,0,0,0.5)', zIndex: 1000, overflow: 'hidden',
        }}>
          <div style={{ padding: '16px', borderBottom: '1px solid var(--border)', background: 'var(--bg-2)' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <div style={{ width: 32, height: 32, borderRadius: '50%', background: 'var(--bg-4)', border: '1px solid var(--border)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                <User size={16} color="var(--text-3)" />
              </div>
              <div>
                <div style={{ fontSize: 14, fontWeight: 700, color: '#fff' }}>{displayName}</div>
                <div style={{ fontSize: 11, color: 'var(--text-3)' }}>{email}</div>
              </div>
            </div>
          </div>

          <div style={{ padding: 6 }}>
            <MenuRow
              icon={<LogOut size={14} />}
              label="Sign Out"
              color="var(--text-2)"
              onClick={() => onSignOut ? onSignOut() : api.logout().then(() => window.location.href = '/login')}
            />

            <div style={{ height: 1, background: 'var(--border)', margin: '4px 0' }} />

            <MenuRow
              icon={<Trash2 size={14} />}
              label={confirmDelete ? '⚠ Click to confirm - IRREVERSIBLE' : 'Delete Account'}
              sublabel={confirmDelete ? 'All alerts and events will be wiped' : 'Permanently wipes all your data'}
              color={confirmDelete ? 'var(--crit)' : '#fca5a5'}
              onClick={handleDeleteAccount}
              disabled={deleting}
              danger
            />
          </div>
        </div>
      )}
    </div>
  )
}

function MenuRow({
  icon, label, sublabel, color, onClick, disabled, danger
}: {
  icon: React.ReactNode
  label: string
  sublabel?: string
  color: string
  onClick: () => void
  disabled?: boolean
  danger?: boolean
}) {
  const [hover, setHover] = useState(false)
  return (
    <button
      onClick={onClick}
      disabled={disabled}
      onMouseEnter={() => setHover(true)}
      onMouseLeave={() => setHover(false)}
      style={{
        display: 'flex', alignItems: 'flex-start', gap: 10, width: '100%',
        padding: '8px 10px',
        background: hover ? (danger ? 'rgba(239,68,68,0.1)' : 'var(--bg-3)') : 'transparent',
        border: 'none', borderRadius: 7,
        cursor: disabled ? 'not-allowed' : 'pointer',
        opacity: disabled ? 0.6 : 1, textAlign: 'left', transition: 'background 0.1s',
      }}
    >
      <span style={{ color, marginTop: 1, flexShrink: 0 }}>{icon}</span>
      <div>
        <div style={{ fontSize: 13, fontWeight: 600, color, lineHeight: 1.2 }}>{label}</div>
        {sublabel && <div style={{ fontSize: 11, color: 'var(--text-3)', marginTop: 2 }}>{sublabel}</div>}
      </div>
    </button>
  )
}
