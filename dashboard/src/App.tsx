import { Routes, Route, Navigate, useNavigate, useLocation } from 'react-router-dom'
import Topbar from './components/Topbar'
import Overview from './pages/Overview'
import ThreatHunt from './pages/ThreatHunt'
import RulesEngine from './pages/RulesEngine'
import AdminPanel from './pages/AdminPanel'
import Firehose from './pages/Firehose'
import EndpointDetails from './pages/EndpointDetails'
import { Login } from './pages/Login'
import ErrorBoundary from './components/ErrorBoundary'
import { useState, useEffect } from 'react'
import { api } from './api/client'

interface UserIdentity {
  email: string
  role: 'admin' | 'user'
  enrollToken: string
  serverIp: string
}

export default function App() {
  const [user, setUser]               = useState<UserIdentity | null>(null)
  const [isCheckingAuth, setChecking] = useState(true)
  const navigate = useNavigate()
  const location = useLocation()

  useEffect(() => {
    let mounted = true
    const safetyTimer = setTimeout(() => { if (mounted) setChecking(false) }, 3000)

    api.getMe()
      .then(me => {
        if (!mounted) return
        if (!me.authenticated) { setChecking(false); return }
        setUser({ email: me.email, role: me.role, enrollToken: me.enroll_token, serverIp: me.server_ip })
        setChecking(false)
      })
      .catch(() => { if (mounted) setChecking(false) })
      .finally(() => clearTimeout(safetyTimer))

    return () => { mounted = false; clearTimeout(safetyTimer) }
  }, [])

  const handleSignOut = async () => {
    try { await api.logout() } finally {
      setUser(null)
      navigate('/login', { replace: true })
    }
  }

  if (isCheckingAuth) {
    return (
      <div style={{
        height: '100vh', width: '100vw', background: 'var(--bg)',
        display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center',
        gap: 16, color: 'var(--text-2)', fontFamily: 'inherit'
      }}>
        <div className="spinner-lg" />
        <span style={{ fontSize: 13, fontWeight: 500, letterSpacing: '0.5px', color: 'var(--text-3)' }}>
          Loading Eyxa EDR Control Plane...
        </span>
      </div>
    )
  }

  if (!user) {
    if (location.pathname !== '/login') {
      return <Navigate to="/login" replace />
    }
    return <Login onLoginSuccess={(u) => {
      setUser(u)
      navigate('/', { replace: true })
    }} />
  }

  if (location.pathname === '/login') {
    return <Navigate to="/" replace />
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100vh', background: 'var(--bg)', overflow: 'hidden' }}>
      <Topbar user={user} onSignOut={handleSignOut} isAdmin={user.role === 'admin'} />

      <div style={{ display: 'flex', flex: 1, overflow: 'hidden', padding: '12px', paddingTop: 8 }}>
        <div style={{ display: 'flex', flexDirection: 'column', flex: 1, overflow: 'hidden', borderRadius: 12 }}>
          <Routes>
            <Route path="/" element={
              <ErrorBoundary fallbackTitle="Overview Error">
                <Overview user={user} />
              </ErrorBoundary>
            } />
            <Route path="/hunt" element={
              <ErrorBoundary fallbackTitle="Threat Hunt Error">
                <ThreatHunt />
              </ErrorBoundary>
            } />
            <Route path="/hunt/:hostId" element={
              <ErrorBoundary fallbackTitle="Threat Hunt Error">
                <ThreatHunt />
              </ErrorBoundary>
            } />
            <Route path="/rules" element={
              <ErrorBoundary fallbackTitle="Rules Engine Error">
                <RulesEngine />
              </ErrorBoundary>
            } />
            <Route path="/hosts/:hostId" element={
              <ErrorBoundary fallbackTitle="Endpoint Error">
                <EndpointDetails />
              </ErrorBoundary>
            } />
            <Route path="/firehose" element={
              <ErrorBoundary fallbackTitle="Firehose Error">
                <Firehose />
              </ErrorBoundary>
            } />
            {user.role === 'admin' && (
              <Route path="/admin" element={
                <ErrorBoundary fallbackTitle="Admin Panel Error">
                  <AdminPanel />
                </ErrorBoundary>
              } />
            )}
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </div>
      </div>
    </div>
  )
}
