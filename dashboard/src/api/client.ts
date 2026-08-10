import axios from 'axios'

export const http = axios.create({
  baseURL: '/api',
  headers: {
    'Content-Type': 'application/json',
  },
  withCredentials: true, // Send HttpOnly JWT cookie
})

// 401 interceptor: redirect to login if unauthorized
http.interceptors.response.use(
  r => r,
  err => {
    if (err.response?.status === 401 && window.location.pathname !== '/login') {
      window.location.href = '/login'
    }
    return Promise.reject(err)
  }
)

export interface Alert {
  alert_id: string
  rule_id?: string
  source_layer: string
  technique_id: string | null
  rule_name: string
  severity_score: number
  raw_event_ref: string | null
  source_table: string | null
  host_id: string | null
  created_at: string
  suppressed: boolean
  summary?: string
  event_id?: number
  channel?: string | null
  process_chain?: {
    self?: { image?: string, command_line?: string }
  }
  status?: 'open' | 'investigated'
  investigated_by?: string | null
  investigated_at?: string | null
  tags?: string[]
}

export interface Stats {
  row_counts: Record<string, number>
  severity_counts: { crit: number; high: number; med: number; low: number }
  last_alert?: string
  utc: string
}

export interface HealthStatus {
  status: 'healthy' | 'degraded' | 'empty'
  db_exists: boolean
  utc: string
  pipeline: Record<string, number>
  last_event?: Record<string, unknown> | null
  last_alert?: Record<string, unknown> | null
  lag_seconds: number | null
  warnings: string[]
}

export interface HardwareInventory {
  os_build: string
  cpu: string
  ram_mb: number
  gpus?: string[]
  network: { name: string, mac: string }[]
  storage: { drive: number, serial: string }[]
}

export interface LiveStats {
  cpu_usage_pct: number
  ram_usage_pct: number
  disk_usage_pct: number
  disk_read_kbps: number
  disk_write_kbps: number
  net_recv_kbps: number
  net_sent_kbps: number
}

export interface RegisteredEndpoint {
  agent_id: number
  host_id: string
  pc_name: string
  registered_at: string | null
  last_seen: string | null
  inventory?: string | HardwareInventory
}

export interface Command {
  id: number
  agent_id: number
  action: string
  payload: string
  status: 'pending' | 'sent' | 'completed' | 'failed'
  result?: string
  created_at: string
}

export interface SigmaRule {
  rule_id: string
  title: string
  description: string
  date: string
  severity: string
  technique_ids: string[]
  tags: string[]
  enabled: boolean
  is_custom: boolean
  is_global: boolean
  hit_count: number
  last_fired_at: number | null
}

export interface TimelineEvent {
  event_type: string
  id: string
  label: string
  event_timestamp: string
  raw_json?: string
  severity_score?: number
  wazuh_ts_epoch?: number
}

export interface AmsiEvent {
  pid: number
  process_guid: string
  content_name: string
  content_hex: string
  scan_result: number
  host_id: string
  event_timestamp: string
}

export interface RuleStat {
  rule_id:       string
  title:         string
  severity:      string
  technique_ids?: string[]
  tags?:         string[]
  hit_count:     number
  last_fired_at: number | null
  noise_score?:  number
  enabled?:      number
  is_custom?:    number
  uploaded_by?:  string | null
  agent_count?:  number
  days_active?:  number
  hours_active?: number
  active_time_str?: string
  is_dead?:      boolean
  is_new?:       boolean
  is_high_noise?: boolean
  false_positive_count?: number
}

export const api = {
  // Auth
  getMe: () => http.get('/auth/me').then(r => r.data),
  login: (email: string, password: string) => http.post('/auth/login', { email, password }).then(r => r.data),
  logout: () => http.post('/auth/logout').then(r => r.data),

  // Overview / Dashboard
  getStats: () => http.get<Stats>('/stats').then(r => r.data),
  getHealth: () => http.get<HealthStatus>('/health').then(r => r.data),
  getHosts: () => http.get<{ hosts: RegisteredEndpoint[] }>('/hosts').then(r => r.data),
  deleteHost: (hostId: string) => http.delete(`/hosts/${encodeURIComponent(hostId)}`).then(r => r.data),
  purgeHost: (hostId: string) => http.delete(`/hosts/${encodeURIComponent(hostId)}/purge`).then(r => r.data),
  revokeHost: (hostId: string) => http.get(`/hosts/${encodeURIComponent(hostId)}/revoke`).then(r => r.data),

  // Alerts
  getAlerts: (params?: { limit?: number; offset?: number; severity_min?: number; technique?: string }) =>
    http.get<{ total: number; limit: number; offset: number; alerts: Alert[] }>('/alerts', { params }).then(r => r.data),

  getAlert: (id: string) => http.get<Alert>(`/alerts/${id}`).then(r => r.data),
  getAlertEvidence: (id: string) => http.get(`/alerts/${id}/evidence`).then(r => r.data),
  triggerTestAlert: () => http.post('/alerts/test').then(r => r.data),

  // AI Assistant
  getAiSchema: () => http.get<{ yaml_content: string }>('/config/ai_schema').then(r => r.data),
  getAiSchemaSample: (eventId?: number | string) => http.get<{ sample: string }>(`/config/ai_schema/sample${eventId ? `?event_id=${eventId}` : ''}`).then(r => r.data),
  getAiKey: () => http.get<{ api_key: string, model_id: string }>('/config/ai_key').then(r => r.data),
  saveAiSchema: (yaml_content: string) => http.post('/config/ai_schema', { yaml_content }).then(r => r.data),
  saveAiKey: (api_key: string, model_id: string) => http.post('/config/ai_key', { api_key, model_id }).then(r => r.data),
  aiInvestigate: (alertId: string | number) => http.post<{ analysis: any; raw_event_count: number; compressed_event_count: number; layer1_count: number; layer2_count: number; truncated: boolean }>(`/alerts/${alertId}/ai_investigate`).then(r => r.data),

  // Rules
  getRules: () => http.get<{ count: number; rules: SigmaRule[] }>('/rules').then(r => r.data),
  getRuleStats: () => http.get<{ stats: any[] }>('/rules/stats').then(r => r.data),
  toggleRule: (ruleId: string, enabled: boolean) =>
    http.post(`/rules/${ruleId}/toggle`, { enabled }).then(r => r.data),
  getRuleYaml: (ruleId: string) => http.get<{ rule_id: string; yaml: string }>(`/rules/${ruleId}/yaml`).then(r => r.data),
  getRuleSql: (ruleId: string) => http.get<{ rule_id: string; sql: string }>(`/rules/${ruleId}/sql`).then(r => r.data),
  updateRuleYaml: (ruleId: string, yaml: string) => http.put(`/rules/${ruleId}/yaml`, { yaml }).then(r => r.data),
  updateRuleMeta: (ruleId: string, meta: { title: string; severity: string; technique_ids: string[]; tags: string[] }) =>
    http.put(`/rules/${ruleId}/meta`, meta).then(r => r.data),
  uploadRule: (yamlText: string) => {
    const form = new FormData()
    form.append('yaml_text', yamlText)
    return fetch('/api/rules/upload', { method: 'POST', body: form }).then(r => r.json())
  },
  deleteRule: (ruleId: string) => http.delete(`/rules/${ruleId}`).then(r => r.data),

  // Threat Hunt
  getTimeline: (params: { host_id?: string; alert_id?: number; hours?: number; since_epoch?: number, cursor?: string, direction?: 'initial' | 'older' | 'newer', limit?: number }) =>
    http.get<{ events: any[] }>('/timeline', { params }).then(r => r.data),
  getProcessTree: (params: { root_guid?: string }) =>
    http.get('/process-tree', { params }).then(r => r.data),
  getPivotEvents: (processGuid: string, type: 'network' | 'file' | 'registry' | 'process') =>
    http.get<{ events: any[] }>(`/events/${processGuid}`, { params: { type } }).then(r => r.data),
  getAmsiEvents: (params?: { limit?: number; offset?: number; detected_only?: boolean }) =>
    http.get<{ total: number; limit: number; offset: number; events: AmsiEvent[] }>('/amsi', { params }).then(r => r.data),

  // Admin
  adminGetAllowedUsers: () => http.get('/admin/allowed-users').then(r => r.data),
  adminAddAllowedUser: (email: string, password?: string) => http.post('/admin/allowed-users', { email, password }).then(r => r.data),
  adminRemoveAllowedUser: (email: string) => http.delete(`/admin/allowed-users/${encodeURIComponent(email)}`).then(r => r.data),
  adminGetStats: () => http.get('/admin/stats').then(r => r.data),
  adminUpdateRole: (userId: number, role: string) => http.put(`/admin/users/${userId}/role`, { role }).then(r => r.data),
  adminUpdatePassword: (userId: number, password: string) => http.put(`/admin/users/${userId}/password`, { password }).then(r => r.data),
  adminPurgeUser: (userId: number) => http.delete(`/admin/users/${userId}/purge`).then(r => r.data),
  adminPurgeAgent: (agentId: string) => http.delete(`/admin/agents/${agentId}/purge`).then(r => r.data),
  adminDeleteAgent: (agentId: string) => http.delete(`/admin/agents/${agentId}`).then(r => r.data),
  adminRevokeAgent: (agentId: string) => http.get(`/admin/agents/${agentId}/revoke`).then(r => r.data),
  adminVacuumDatabase: () => http.post('/admin/vacuum').then(r => r.data),
  deleteMyData: () => http.delete('/delete-my-data').then(r => r.data),
  getAgents: () => http.get('/agents').then(r => r.data),

  // Alert status + tags (backend-persisted)
  updateAlertStatus: (alertId: string, status: 'investigated' | 'open') =>
    http.post(`/alerts/${alertId}/status`, { status }).then(r => r.data),
  updateAlertTag: (alertId: string, action: 'add' | 'remove', tag: string) =>
    http.post(`/alerts/${alertId}/tags`, { action, tag }).then(r => r.data),

  // Commands
  createCommand: (agentId: number, action: string, payload: any) =>
    http.post('/commands', { agent_id: agentId, action, payload }).then(r => r.data),
  getCommands: (agentId: number) =>
    http.get<Command[]>('/commands', { params: { agent_id: agentId } }).then(r => r.data),
  deleteQueuedCommands: (agentId: number) =>
    http.delete('/commands', { params: { agent_id: agentId } }).then(r => r.data),
  deleteCommand: (cmdId: number) =>
    http.delete(`/commands/${cmdId}`).then(r => r.data),
}
