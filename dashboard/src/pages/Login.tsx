import React, { useState } from 'react'
import { Shield, Lock, Mail, ArrowRight, Activity } from 'lucide-react'
import { api } from '../api/client'

interface LoginProps {
  onLoginSuccess: (user: { email: string; role: 'admin' | 'user'; enrollToken: string; serverIp: string }) => void
}

export function Login({ onLoginSuccess }: LoginProps) {
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!email || !password) {
      setError('Please enter both email and password.')
      return
    }

    setLoading(true)
    setError('')

    try {
      await api.login(email, password)
      const me = await api.getMe()
      if (me.authenticated) {
        onLoginSuccess({ email: me.email, role: me.role, enrollToken: me.enroll_token, serverIp: me.server_ip })
      } else {
        setError('Login succeeded but session could not be verified.')
      }
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Invalid email or password.')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div style={{
      minHeight: '100vh',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      background: '#0d0d0f',
      position: 'relative',
      overflow: 'hidden'
    }}>
      {/* Background glowing decorations */}
      <div style={{
        position: 'absolute', top: '10%', left: '15%', width: 400, height: 400,
        background: 'radial-gradient(circle, rgba(239,68,68,0.15) 0%, rgba(0,0,0,0) 70%)',
        filter: 'blur(40px)'
      }} />
      <div style={{
        position: 'absolute', bottom: '10%', right: '15%', width: 500, height: 500,
        background: 'radial-gradient(circle, rgba(185,28,28,0.1) 0%, rgba(0,0,0,0) 70%)',
        filter: 'blur(60px)'
      }} />

      <div style={{
        width: '100%',
        maxWidth: 420,
        padding: '40px',
        background: 'rgba(20, 20, 22, 0.7)',
        backdropFilter: 'blur(20px)',
        border: '1px solid rgba(255, 255, 255, 0.08)',
        borderRadius: 24,
        boxShadow: '0 24px 48px rgba(0,0,0,0.5)',
        zIndex: 1,
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center'
      }}>
        {/* Shield Logo */}
        <div style={{
          width: 56, height: 56, borderRadius: 16,
          background: 'linear-gradient(135deg, rgba(239,68,68,0.2) 0%, rgba(185,28,28,0.2) 100%)',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          border: '1px solid rgba(239,68,68,0.4)',
          marginBottom: 24
        }}>
          <Shield size={28} color="#ef4444" />
        </div>

        <h1 style={{ fontSize: 24, fontWeight: 900, color: '#fff', marginBottom: 8, letterSpacing: '-0.5px' }}>
          Eyxa EDR
        </h1>
        <p style={{ fontSize: 14, color: 'var(--text-3)', marginBottom: 32 }}>
          Enterprise Endpoint Detection & Response
        </p>

        <form onSubmit={handleSubmit} style={{ width: '100%', display: 'flex', flexDirection: 'column', gap: 16 }}>
          {error && (
            <div style={{
              padding: '12px 16px', background: 'rgba(239,68,68,0.1)', border: '1px solid rgba(239,68,68,0.3)',
              borderRadius: 12, color: '#fca5a5', fontSize: 13, display: 'flex', alignItems: 'center', gap: 8
            }}>
              <Activity size={16} />
              {error}
            </div>
          )}

          <div style={{ position: 'relative' }}>
            <div style={{ position: 'absolute', left: 14, top: '50%', transform: 'translateY(-50%)', color: 'var(--text-3)' }}>
              <Mail size={18} />
            </div>
            <input
              type="email"
              placeholder="Email address"
              value={email}
              onChange={e => setEmail(e.target.value)}
              style={{
                width: '100%', padding: '14px 16px 14px 44px',
                background: 'rgba(0,0,0,0.4)', border: '1px solid rgba(255,255,255,0.1)',
                borderRadius: 12, color: '#fff', fontSize: 14, outline: 'none'
              }}
              autoFocus
            />
          </div>

          <div style={{ position: 'relative' }}>
            <div style={{ position: 'absolute', left: 14, top: '50%', transform: 'translateY(-50%)', color: 'var(--text-3)' }}>
              <Lock size={18} />
            </div>
            <input
              type="password"
              placeholder="Password"
              value={password}
              onChange={e => setPassword(e.target.value)}
              style={{
                width: '100%', padding: '14px 16px 14px 44px',
                background: 'rgba(0,0,0,0.4)', border: '1px solid rgba(255,255,255,0.1)',
                borderRadius: 12, color: '#fff', fontSize: 14, outline: 'none'
              }}
            />
          </div>

          <button
            type="submit"
            disabled={loading}
            style={{
              width: '100%', padding: '14px', marginTop: 8,
              background: loading ? 'var(--bg-3)' : 'linear-gradient(135deg, #ef4444 0%, #b91c1c 100%)',
              color: loading ? 'var(--text-3)' : '#fff',
              border: 'none', borderRadius: 12, fontSize: 14, fontWeight: 700,
              cursor: loading ? 'not-allowed' : 'pointer',
              display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8,
              boxShadow: '0 4px 14px rgba(239,68,68,0.4)'
            }}
          >
            {loading ? 'Authenticating...' : 'Sign In'}
            {!loading && <ArrowRight size={16} />}
          </button>
        </form>

        <div style={{ marginTop: 32, fontSize: 12, color: 'var(--text-3)' }}>
          Eyxa Security Control Plane
        </div>
      </div>
    </div>
  )
}
