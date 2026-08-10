import { useEffect, useState } from 'react'
import { Users, UserPlus, Trash2, RefreshCw, Lock, ShieldAlert, Cpu, Database, Activity, HardDrive, Key, UserCog, Server, Trash, Shield, MonitorOff, Monitor, Eye, EyeOff } from 'lucide-react'
import { api } from '../api/client'
import { useToast } from '../context/ToastContext'

export default function AdminPanel() {
  const toast = useToast()
  
  // Data State
  const [users, setUsers] = useState<any[]>([])
  const [stats, setStats] = useState<any>(null)
  
  // UI State
  const [loading, setLoading] = useState(true)
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [adding, setAdding] = useState(false)
  const [showAddPass, setShowAddPass] = useState(false)
  const [showPass, setShowPass] = useState<Record<number, boolean>>({})
  const [activeActions, setActiveActions] = useState<Record<string, boolean>>({})

  const loadUsers = async () => {
    try {
      const u = await api.adminGetAllowedUsers()
      setUsers(Array.isArray(u) ? u : [])
    } catch (e) {
      console.error(e)
    }
  }

  const loadStats = async () => {
    try {
      const s = await api.adminGetStats()
      setStats(s)
    } catch (e) {
      console.error(e)
    }
  }

  useEffect(() => {
    let active = true;
    const init = async () => {
      await Promise.all([loadUsers(), loadStats()])
      if (active) setLoading(false)
    }
    init()
    
    // Live stats polling every 1 second
    const interval = setInterval(() => { if(active) loadStats() }, 1000)
    return () => { active = false; clearInterval(interval) }
  }, [])

  // ------------------------------------------------------------------
  // Actions
  // ------------------------------------------------------------------
  const setAction = (key: string, val: boolean) => setActiveActions(p => ({ ...p, [key]: val }))

  const handleAddUser = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!email.trim() || !password.trim()) return
    setAdding(true)
    try {
      await api.adminAddAllowedUser(email, password)
      toast.success('Account created', email)
      setEmail('')
      setPassword('')
      loadUsers()
    } catch (e: any) {
      toast.error('Failed to create account', e?.response?.data?.detail || 'Unknown error')
    } finally {
      setAdding(false)
    }
  }

  const handleRemoveUser = async (userEmail: string) => {
    if (!window.confirm(`Delete user account "${userEmail}" and all their data?`)) return
    setAction(`remove_user_${userEmail}`, true)
    try {
      await api.adminRemoveAllowedUser(userEmail)
      toast.success('Account removed', userEmail)
      loadUsers()
    } catch {
      toast.error('Failed to remove user')
    } finally {
      setAction(`remove_user_${userEmail}`, false)
    }
  }

  const handlePurgeUser = async (userId: number, email: string) => {
    if (!window.confirm(`Purge all events and alerts for ${email}? (Keeps account and agents)`)) return
    setAction(`purge_user_${userId}`, true)
    try {
      await api.adminPurgeUser(userId)
      toast.success('Data purged', `All logs for ${email} wiped.`)
    } catch {
      toast.error('Failed to purge data')
    } finally {
      setAction(`purge_user_${userId}`, false)
    }
  }

  const handleChangeRole = async (userId: number, role: string) => {
    setAction(`role_user_${userId}`, true)
    try {
      await api.adminUpdateRole(userId, role)
      toast.success('Role updated')
      loadUsers()
    } catch {
      toast.error('Failed to update role')
    } finally {
      setAction(`role_user_${userId}`, false)
    }
  }

  const handleChangePassword = async (userId: number, currentPlain: string) => {
    const newPass = window.prompt("Enter new password for user:", currentPlain)
    if (!newPass || newPass === currentPlain) return
    
    setAction(`pass_user_${userId}`, true)
    try {
      await api.adminUpdatePassword(userId, newPass)
      toast.success('Password updated')
      loadUsers()
    } catch {
      toast.error('Failed to update password')
    } finally {
      setAction(`pass_user_${userId}`, false)
    }
  }

  const handleAgentAction = async (agentId: string, actionName: string) => {
    if (!window.confirm(`Are you sure you want to ${actionName.toUpperCase()} agent ${agentId}?`)) return
    setAction(`agent_${actionName}_${agentId}`, true)
    try {
      if (actionName === 'purge') await api.adminPurgeAgent(agentId)
      if (actionName === 'revoke') await api.adminRevokeAgent(agentId)
      if (actionName === 'delete') await api.adminDeleteAgent(agentId)
      
      toast.success(`Agent ${actionName} successful`)
      if (actionName === 'delete') loadUsers() // reload to remove it from list
    } catch {
      toast.error(`Failed to ${actionName} agent`)
    } finally {
      setAction(`agent_${actionName}_${agentId}`, false)
    }
  }

  const handleVacuum = async () => {
    if (!window.confirm('Are you sure you want to reclaim space? This might take a few seconds on a large database.')) return
    setAction('vacuum', true)
    try {
      await api.adminVacuumDatabase()
      toast.success('Database vacuumed successfully. Space reclaimed!')
      loadStats()
    } catch {
      toast.error('Failed to vacuum database')
    } finally {
      setAction('vacuum', false)
    }
  }

  if (loading) {
    return (
      <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
        <div className="spinner" />
      </div>
    )
  }

  return (
    <div style={{ flex: 1, overflow: 'auto', padding: 24, display: 'flex', flexDirection: 'column', gap: 20 }}>

      {/* Header */}
      <div className="card" style={{ padding: 18 }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
              <Lock size={16} color="var(--accent)" />
              <span style={{ fontSize: 11, fontWeight: 700, letterSpacing: '1px', textTransform: 'uppercase', color: 'var(--text-3)' }}>
                System Administration
              </span>
            </div>
            <h1 style={{ fontSize: 22, fontWeight: 800, color: 'var(--text)', letterSpacing: '-0.5px' }}>
              
            </h1>
          </div>
          <button 
            onClick={handleVacuum} 
            disabled={activeActions['vacuum']}
            className="btn btn-secondary" 
            style={{ display: 'flex', alignItems: 'center', gap: 6 }}
          >
            {activeActions['vacuum'] ? <div className="spinner-sm" /> : <Database size={16} />}
            Reclaim Space (Vacuum)
          </button>
        </div>
      </div>

      {/* Deep System Stats */}
      {stats && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 16 }}>
          <div className="card" style={{ padding: 16, display: 'flex', flexDirection: 'column', gap: 8 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, color: 'var(--text-2)' }}>
              <Cpu size={16} color="var(--alert-high)" /> <span style={{ fontSize: 13, fontWeight: 600 }}>CPU Usage</span>
            </div>
            <div style={{ fontSize: 24, fontWeight: 800, color: 'var(--text)' }}>{stats.cpu_percent.toFixed(1)}%</div>
          </div>
          <div className="card" style={{ padding: 16, display: 'flex', flexDirection: 'column', gap: 8 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, color: 'var(--text-2)' }}>
              <Activity size={16} color="var(--accent)" /> <span style={{ fontSize: 13, fontWeight: 600 }}>RAM Usage</span>
            </div>
            <div style={{ fontSize: 24, fontWeight: 800, color: 'var(--text)' }}>{stats.ram_percent.toFixed(1)}%</div>
            <div style={{ fontSize: 11, color: 'var(--text-3)' }}>{stats.ram_used_gb} / {stats.ram_total_gb} GB</div>
          </div>
          <div className="card" style={{ padding: 16, display: 'flex', flexDirection: 'column', gap: 8 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, color: 'var(--text-2)' }}>
              <Database size={16} color="var(--alert-med)" /> <span style={{ fontSize: 13, fontWeight: 600 }}>Database Size</span>
            </div>
            <div style={{ fontSize: 24, fontWeight: 800, color: 'var(--text)' }}>{stats.db_size_mb} MB</div>
          </div>
          <div className="card" style={{ padding: 16, display: 'flex', flexDirection: 'column', gap: 8 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, color: 'var(--text-2)' }}>
              <Server size={16} color="var(--text-2)" /> <span style={{ fontSize: 13, fontWeight: 600 }}>Global Firehose</span>
            </div>
            <div style={{ fontSize: 24, fontWeight: 800, color: 'var(--text)' }}>{stats.events.toLocaleString()} logs</div>
            <div style={{ fontSize: 11, color: 'var(--alert-high)' }}>{stats.alerts.toLocaleString()} alerts triggered</div>
          </div>
        </div>
      )}

      {/* User Management Section */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
        <h2 style={{ fontSize: 16, fontWeight: 700, color: 'var(--text)', borderBottom: '1px solid var(--border)', paddingBottom: 8 }}>
          Users & Enrolled Agents
        </h2>
        
        {/* Add user form */}
        <div className="card" style={{ padding: 16 }}>
          <form onSubmit={handleAddUser} style={{ display: 'flex', gap: 12, alignItems: 'center' }}>
            <UserPlus size={16} color="var(--text-3)" />
            <input
              placeholder="New User Email"
              type="email"
              value={email}
              onChange={e => setEmail(e.target.value)}
              style={{ flex: 1, padding: '8px 12px', fontSize: 13 }}
              required
            />
            <div style={{ flex: 1, position: 'relative', display: 'flex', alignItems: 'center' }}>
              <input
                type={showAddPass ? "text" : "password"}
                placeholder="Initial Password"
                value={password}
                onChange={e => setPassword(e.target.value)}
                style={{ width: '100%', padding: '8px 36px 8px 12px', fontSize: 13 }}
                required
              />
              <button 
                type="button" 
                onClick={() => setShowAddPass(!showAddPass)}
                style={{ position: 'absolute', right: 8, background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-3)' }}
              >
                {showAddPass ? <EyeOff size={16} /> : <Eye size={16} />}
              </button>
            </div>
            <button type="submit" disabled={adding} className="btn btn-primary">
              {adding ? <div className="spinner-sm" /> : 'Add New User'}
            </button>
          </form>
        </div>

        {/* User Cards */}
        {users.map((u: any) => (
          <div key={u.id} className="card" style={{ padding: 0, overflow: 'hidden' }}>
            {/* User Header */}
            <div style={{ padding: 16, background: 'var(--bg-2)', borderBottom: '1px solid var(--border)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div>
                <div style={{ fontSize: 15, fontWeight: 700, color: 'var(--text)', display: 'flex', alignItems: 'center', gap: 8 }}>
                  {u.email}
                  {u.role === 'admin' && <span style={{ background: 'var(--accent)', color: '#000', fontSize: 10, padding: '2px 6px', borderRadius: 4, fontWeight: 800 }}>ADMIN</span>}
                </div>
                <div style={{ fontSize: 12, color: 'var(--text-3)', marginTop: 4 }}>ID: {u.id} · Joined: {new Date(u.added_at).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })}</div>
              </div>
              <div style={{ display: 'flex', gap: 8 }}>
                <button
                  onClick={() => handlePurgeUser(u.id, u.email)}
                  disabled={activeActions[`purge_user_${u.id}`]}
                  className="btn btn-sm btn-secondary"
                  title="Delete all telemetry and alerts for this user"
                >
                  {activeActions[`purge_user_${u.id}`] ? <div className="spinner-sm"/> : <Trash size={14} />} Purge Data
                </button>
                <button
                  onClick={() => handleRemoveUser(u.email)}
                  disabled={activeActions[`remove_user_${u.email}`]}
                  className="btn btn-sm btn-danger"
                  title="Hard delete user and completely wipe existence"
                >
                  {activeActions[`remove_user_${u.email}`] ? <div className="spinner-sm"/> : <Trash2 size={14} />} Delete
                </button>
              </div>
            </div>

            {/* User Details & Agents */}
            <div style={{ padding: 16, display: 'flex', flexDirection: 'column', gap: 16 }}>
              {/* Credentials & Role */}
              <div style={{ display: 'flex', gap: 24, padding: 12, background: 'var(--bg-3)', borderRadius: 8, border: '1px dashed var(--border)' }}>
                <div style={{ flex: 1 }}>
                  <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-3)', marginBottom: 4, textTransform: 'uppercase' }}>Plaintext Password</div>
                  <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                    <code style={{ fontSize: 13, color: 'var(--alert-high)', background: 'var(--bg)', padding: '4px 8px', borderRadius: 4, letterSpacing: '1px' }}>
                      {showPass[u.id] ? (u.password_plaintext || '<HASH ONLY>') : '••••••••'}
                    </code>
                    <button onClick={() => setShowPass(p => ({...p, [u.id]: !p[u.id]}))} className="btn btn-sm" style={{ padding: '4px 6px', background: 'transparent', border: '1px solid var(--border)' }}>
                      {showPass[u.id] ? <EyeOff size={14} color="var(--text-3)" /> : <Eye size={14} color="var(--text-3)" />}
                    </button>
                    <button onClick={() => handleChangePassword(u.id, u.password_plaintext)} className="btn btn-sm btn-secondary">Change</button>
                  </div>
                </div>
                <div style={{ flex: 1 }}>
                  <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-3)', marginBottom: 4, textTransform: 'uppercase' }}>System Role</div>
                  <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                    <select 
                      value={u.role} 
                      onChange={(e) => handleChangeRole(u.id, e.target.value)}
                      style={{ padding: '5px 8px', fontSize: 13, background: 'var(--bg)', color: 'var(--text)', border: '1px solid var(--border)', borderRadius: 4 }}
                    >
                      <option value="user">User</option>
                      <option value="admin">Administrator</option>
                    </select>
                  </div>
                </div>
              </div>

              {/* Agents List */}
              <div>
                <div style={{ fontSize: 12, fontWeight: 700, color: 'var(--text-2)', marginBottom: 8, display: 'flex', alignItems: 'center', gap: 6 }}>
                  <Monitor size={14} /> Enrolled Agents ({u.agent_count})
                </div>
                {u.agents.length === 0 ? (
                  <div style={{ fontSize: 13, color: 'var(--text-3)', fontStyle: 'italic', padding: '12px 16px', background: 'var(--bg-3)', borderRadius: 8 }}>
                    No agents enrolled yet.
                  </div>
                ) : (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                    {u.agents.map((a: any) => (
                      <div key={a.agent_id} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '12px 16px', background: 'var(--bg-3)', borderRadius: 8, borderLeft: '3px solid var(--accent)' }}>
                        <div>
                          <div style={{ fontSize: 14, fontWeight: 600, color: 'var(--text)' }}>{a.hostname}</div>
                          <div style={{ fontSize: 11, color: 'var(--text-3)', marginTop: 2, fontFamily: 'monospace' }}>ID: {a.agent_id} | Token: {a.agent_token.substring(0, 16)}...</div>
                        </div>
                        <div style={{ display: 'flex', gap: 6 }}>
                          <button onClick={() => handleAgentAction(a.agent_id, 'purge')} className="btn btn-sm btn-secondary">
                            {activeActions[`agent_purge_${a.agent_id}`] ? <div className="spinner-sm"/> : <Trash size={12}/>} Purge
                          </button>
                          <button onClick={() => handleAgentAction(a.agent_id, 'revoke')} className="btn btn-sm btn-secondary" title="Revoke connection token">
                            {activeActions[`agent_revoke_${a.agent_id}`] ? <div className="spinner-sm"/> : <MonitorOff size={12}/>} Revoke
                          </button>
                          <button onClick={() => handleAgentAction(a.agent_id, 'delete')} className="btn btn-sm btn-danger">
                            {activeActions[`agent_delete_${a.agent_id}`] ? <div className="spinner-sm"/> : <Trash2 size={12}/>} Delete
                          </button>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}
