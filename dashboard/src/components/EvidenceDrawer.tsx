import { useEffect, useState, ReactNode } from 'react'
import { Shield } from 'lucide-react'
import { api, type Alert } from '../api/client'
import { getCategoryIcon } from '../utils/theme'
import CopyButton from './CopyButton'

interface Props {
  alert: Alert | null
}

function basename(path?: string | null): string {
  if (!path) return 'Unknown'
  return path.split(/[/\\]/).pop() || path
}

function EvidenceSection({ title, icon, count, children }: {
  title: string
  icon: ReactNode
  count?: number
  children: ReactNode
}) {
  return (
    <section style={{ borderBottom: '1px solid var(--border)', padding: '14px 16px' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 10 }}>
        {icon}
        <h3 style={{ fontSize: 12, fontWeight: 800, color: 'var(--text)', textTransform: 'uppercase', letterSpacing: '0.5px' }}>{title}</h3>
        {typeof count === 'number' && (
          <span className="tag" style={{ marginLeft: 'auto' }}>{count}</span>
        )}
      </div>
      {children}
    </section>
  )
}

export default function EvidenceDrawer({ alert }: Props) {
  const [evidence, setEvidence] = useState<any>(null)
  const [loading, setLoading]   = useState(false)

  useEffect(() => {
    if (!alert) {
      setEvidence(null)
      return
    }
    setLoading(true)
    api.getAlertEvidence(alert.alert_id)
      .then(setEvidence)
      .catch(console.error)
      .finally(() => setLoading(false))
  }, [alert])

  if (!alert) {
    return (
      <div className="empty-state" style={{ flex: 1 }}>
        <Shield size={36} />
        <h3>No Alert Selected</h3>
        <p>Select a detection from the alert queue to inspect its complete evidence block.</p>
      </div>
    )
  }

  if (loading) {
    return (
      <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
        <div className="spinner" />
      </div>
    )
  }

  const artifacts = evidence?.artifacts ?? { process: [], network: [], file: [], registry: [] }
  const sourceEv  = evidence?.source_event ?? {}
  const payload   = (() => {
    try { return JSON.parse(sourceEv.payload || '{}') } catch { return {} }
  })()

  return (
    <div style={{ flex: 1, overflowY: 'auto', background: 'var(--bg-1)' }}>
      {/* Alert Header */}
      <div style={{ padding: 16, borderBottom: '1px solid var(--border)', background: 'var(--bg-2)' }}>
        <div style={{ fontSize: 16, fontWeight: 800, color: 'var(--text)', marginBottom: 4 }}>
          {alert.rule_name}
        </div>
        <div style={{ fontSize: 12, color: 'var(--text-3)', display: 'flex', gap: 12 }}>
          <span>Technique: <strong style={{ color: 'var(--accent)' }}>{alert.technique_id || 'N/A'}</strong></span>
          <span>Host: <strong>{alert.host_id || 'Windows Endpoint'}</strong></span>
        </div>
      </div>

      {/* Hybrid Dynamic Artifact Renderer */}
      {Object.entries(artifacts).map(([category, items]: [string, any]) => {
        if (category === 'process') {
          return (
            <EvidenceSection key="process" title="Process Execution" icon={getCategoryIcon('process', 14)} count={items.length}>
              {items.length === 0 ? (
                <div style={{ fontSize: 12, color: 'var(--text-3)' }}>
                  Image: <span style={{ color: 'var(--text-2)', fontFamily: 'monospace' }}>{payload.Image || 'N/A'}</span>
                  <br />
                  Command: <span style={{ color: 'var(--text-2)', fontFamily: 'monospace' }}>{payload.CommandLine || 'N/A'}</span>
                </div>
              ) : (
                items.map((p: any, i: number) => (
                  <div key={i} style={{ background: 'var(--bg-2)', border: '1px solid var(--border)', borderRadius: 6, padding: 10, marginBottom: 6, display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                    <div style={{ flex: 1, overflow: 'hidden' }}>
                      <div style={{ fontSize: 12, fontWeight: 700, color: 'var(--text)', display: 'flex', alignItems: 'center', gap: 6 }}>
                        {basename(p.process_image)} (PID {p.pid})
                      </div>
                      <div style={{ fontSize: 11, color: 'var(--text-3)', fontFamily: 'monospace', marginTop: 2, display: 'flex', alignItems: 'center', gap: 6 }}>
                        {p.command_line}
                      </div>
                    </div>
                    <CopyButton text={`Image: ${p.process_image}\nCommandLine: ${p.command_line}`} />
                  </div>
                ))
              )}
            </EvidenceSection>
          )
        }
        
        if (category === 'network') {
          return (
            <EvidenceSection key="network" title="Network Activity" icon={getCategoryIcon('network', 14)} count={items.length}>
              {items.length === 0 ? (
                <div style={{ fontSize: 12, color: 'var(--text-3)' }}>No network connections observed for this event.</div>
              ) : (
                items.map((net: any, i: number) => (
                  <div key={i} style={{ background: 'var(--bg-2)', border: '1px solid var(--border)', borderRadius: 6, padding: 8, marginBottom: 6 }}>
                    <div style={{ fontSize: 12, color: 'var(--text)', fontWeight: 600 }}>{net.destination_ip}:{net.destination_port}</div>
                  </div>
                ))
              )}
            </EvidenceSection>
          )
        }

        if (category === 'registry') {
          return (
            <EvidenceSection key="registry" title="Registry Modifications" icon={getCategoryIcon('registry', 14)} count={items.length}>
              {items.length === 0 ? (
                <div style={{ fontSize: 12, color: 'var(--text-3)' }}>No registry modifications associated.</div>
              ) : (
                items.map((reg: any, i: number) => (
                  <div key={i} style={{ background: 'var(--bg-2)', border: '1px solid var(--border)', borderRadius: 6, padding: 8, marginBottom: 6 }}>
                    <div style={{ fontSize: 12, color: 'var(--text)', fontFamily: 'monospace', display: 'flex', alignItems: 'center', gap: 6, wordBreak: 'break-all' }}>
                      {reg.target_object}
                      <CopyButton text={reg.target_object} />
                    </div>
                    <div style={{ fontSize: 11, color: 'var(--text-3)', display: 'flex', alignItems: 'center', gap: 6 }}>
                      Details: {reg.details}
                      <CopyButton text={reg.details} />
                    </div>
                  </div>
                ))
              )}
            </EvidenceSection>
          )
        }

        if (category === 'file') {
            return (
              <EvidenceSection key="file" title="File Artifacts" icon={getCategoryIcon('file', 14)} count={items.length}>
                {items.length === 0 ? (
                  <div style={{ fontSize: 12, color: 'var(--text-3)' }}>No file artifacts observed.</div>
                ) : (
                  items.map((f: any, i: number) => (
                    <div key={i} style={{ background: 'var(--bg-2)', border: '1px solid var(--border)', borderRadius: 6, padding: 8, marginBottom: 6 }}>
                      <div style={{ fontSize: 12, color: 'var(--text)', fontFamily: 'monospace', display: 'flex', alignItems: 'center', gap: 6, wordBreak: 'break-all' }}>
                        {f.target_filename}
                        <CopyButton text={f.target_filename} />
                      </div>
                    </div>
                  ))
                )}
              </EvidenceSection>
            )
        }

        // Generic dynamic fallback for any unknown categories
        return (
          <EvidenceSection key={category} title={category} icon={getCategoryIcon(category, 14)} count={items.length}>
            {items.length === 0 ? (
               <div style={{ fontSize: 12, color: 'var(--text-3)' }}>No {category} artifacts observed.</div>
            ) : (
              items.map((item: any, i: number) => (
                <div key={i} style={{ background: 'var(--bg-2)', border: '1px solid var(--border)', borderRadius: 6, padding: 8, marginBottom: 6, display: 'flex', flexDirection: 'column', gap: 4 }}>
                  {Object.entries(item).filter(([k]) => !k.startsWith('_')).map(([k, v]) => (
                    <div key={k} style={{ display: 'flex', gap: 8, alignItems: 'flex-start' }}>
                       <span style={{ fontSize: 10, color: 'var(--text-3)', fontWeight: 600, width: 140, flexShrink: 0, textTransform: 'uppercase', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={k}>{k}</span>
                       <span style={{ fontSize: 11, color: 'var(--text-2)', fontFamily: 'monospace', wordBreak: 'break-all', display: 'flex', alignItems: 'center', gap: 6 }}>
                         {String(v)}
                         <CopyButton text={String(v)} />
                       </span>
                    </div>
                  ))}
                </div>
              ))
            )}
          </EvidenceSection>
        )
      })}
    </div>
  )
}
