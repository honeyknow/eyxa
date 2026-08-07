import { useEffect, useState, useCallback, useRef } from 'react'
import {
  Shield, Search, Database, RefreshCw, Upload, Edit2, Trash2,
  X, Check, AlertCircle, FileText, BarChart2, Globe, User, Copy
} from 'lucide-react'
import { api, type SigmaRule, type RuleStat } from '../api/client'

const SEV_META: Record<string, { label: string; color: string; bg: string }> = {
  critical: { label: 'Critical', color: '#ef4444', bg: 'rgba(239,68,68,0.12)' },
  high: { label: 'High', color: '#f97316', bg: 'rgba(249,115,22,0.12)' },
  medium: { label: 'Medium', color: '#eab308', bg: 'rgba(234,179,8,0.12)' },
  low: { label: 'Low', color: '#22c55e', bg: 'rgba(34,197,94,0.12)' },
  unknown: { label: 'Unknown', color: '#6b7280', bg: 'rgba(107,114,128,0.1)' },
}

function LiveToggle({ enabled, loading, onChange }: {
  enabled: boolean; loading: boolean; onChange: (v: boolean) => void
}) {
  return (
    <button onClick={() => !loading && onChange(!enabled)} title={enabled ? 'Disable' : 'Enable'}
      style={{ width: 36, height: 20, borderRadius: 99, background: loading ? '#6b7280' : enabled ? '#6366f1' : 'var(--border)', border: 'none', cursor: loading ? 'wait' : 'pointer', position: 'relative', transition: 'background 0.2s', flexShrink: 0 }}>
      <div style={{ width: 14, height: 14, borderRadius: '50%', background: '#fff', position: 'absolute', top: 3, left: enabled ? 19 : 3, transition: 'left 0.2s', boxShadow: '0 1px 3px rgba(0,0,0,0.3)' }} />
    </button>
  )
}

const YAML_TEMPLATE = `title: My Custom Detection Rule
id: 00000000-0000-0000-0000-000000000001
status: test
description: Detects suspicious activity.
author: Your Name
date: 2026/01/01
tags:
  - attack.execution
  - attack.t1059.001
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith:
      - '\\\\powershell.exe'
    CommandLine|contains:
      - '-enc'
  condition: selection
falsepositives:
  - Legitimate admin activity
level: high
`

type ModalMode = 'upload' | 'edit'

// Chip/tag input helper
function ChipInput({ values, onChange, placeholder }: { values: string[]; onChange: (v: string[]) => void; placeholder?: string }) {
  const [input, setInput] = useState('')
  const commit = () => {
    const v = input.trim()
    if (v && !values.includes(v)) onChange([...values, v])
    setInput('')
  }
  return (
    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4, background: 'var(--bg-3)', border: '1px solid var(--border)', borderRadius: 7, padding: '6px 8px', minHeight: 38 }}>
      {values.map(v => (
        <span key={v} style={{ display: 'flex', alignItems: 'center', gap: 4, background: 'rgba(99,102,241,0.15)', color: '#6366f1', borderRadius: 4, padding: '2px 8px', fontSize: 11, fontWeight: 600 }}>
          {v}
          <button onClick={() => onChange(values.filter(x => x !== v))} style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#6366f1', padding: 0, lineHeight: 1 }}>×</button>
        </span>
      ))}
      <input value={input} onChange={e => setInput(e.target.value)}
        onKeyDown={e => { if (e.key === 'Enter' || e.key === ',') { e.preventDefault(); commit() } }}
        onBlur={commit}
        placeholder={values.length === 0 ? placeholder : ''}
        style={{ border: 'none', outline: 'none', background: 'transparent', color: 'var(--text)', fontSize: 12, flex: 1, minWidth: 120 }} />
    </div>
  )
}

function YamlModal({ mode, rule, onClose, onSuccess }: { mode: ModalMode; rule?: SigmaRule; onClose: () => void; onSuccess: () => void }) {
  // tabs: 'fields' (edit only) | 'yaml' | 'file' (upload only)
  const [tab, setTab] = useState<'fields' | 'yaml' | 'file'>('fields')
  const [yaml, setYaml] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [success, setSuccess] = useState('')
  const [dragging, setDragging] = useState(false)
  const fileRef = useRef<HTMLInputElement>(null)

  // Fields state (edit mode)
  const [fUuid, setFUuid] = useState(rule?.rule_id ?? crypto.randomUUID())
  const [fTitle, setFTitle] = useState(rule?.title ?? 'My Custom Detection Rule')
  const [fSeverity, setFSeverity] = useState(rule?.severity ?? 'high')
  const [fMitre, setFMitre] = useState<string[]>(rule?.technique_ids ?? ['T1059.001'])
  const [fTags, setFTags] = useState<string[]>(rule?.tags ?? ['attack.execution'])

  useEffect(() => {
    if (mode === 'edit' && rule) {
      setFUuid(rule.rule_id); setFTitle(rule.title); setFSeverity(rule.severity)
      setFMitre(rule.technique_ids ?? []); setFTags(rule.tags ?? [])
      api.getRuleYaml(rule.rule_id).then(d => setYaml(d.yaml)).catch(() => setError('Failed to load YAML'))
    } else { setYaml(YAML_TEMPLATE) }
  }, [mode, rule])

  const submitFields = async () => {
    if (!fTitle.trim()) { setError('Title cannot be empty'); return }
    setLoading(true); setError(''); setSuccess('')
    try {
      if (mode === 'edit' && rule) {
        await api.updateRuleMeta(rule.rule_id, {
          title: fTitle, severity: fSeverity,
          technique_ids: fMitre, tags: fTags,
        })
        setSuccess('Fields saved!')
      } else {
        let finalYaml = yaml
        finalYaml = finalYaml.replace(/^id:\s*.*$/m, `id: ${fUuid}`)
        finalYaml = finalYaml.replace(/^title:\s*.*$/m, `title: ${fTitle}`)
        finalYaml = finalYaml.replace(/^level:\s*.*$/m, `level: ${fSeverity}`)
        const allTags = Array.from(new Set([...fTags, ...fMitre.map(t => 'attack.' + t.toLowerCase())]))
        const tagsBlock = allTags.length > 0 ? `tags:\n` + allTags.map(t => `  - ${t}`).join('\n') : 'tags: []'
        if (/^tags:/m.test(finalYaml)) {
          finalYaml = finalYaml.replace(/^tags:[\s\S]*?(?=^[a-z]+:|\Z)/m, tagsBlock + '\n')
        }
        await api.uploadRule(finalYaml)
        setSuccess('Rule uploaded!')
      }
      setTimeout(() => { onSuccess(); onClose() }, 700)
    } catch (e: any) {
      setError(e?.response?.data?.detail ?? 'Save failed')
    } finally { setLoading(false) }
  }

  const submitYaml = async () => {
    if (!yaml.trim()) { setError('YAML cannot be empty'); return }
    setLoading(true); setError(''); setSuccess('')
    try {
      if (mode === 'edit' && rule) { await api.updateRuleYaml(rule.rule_id, yaml); setSuccess('YAML saved!') }
      else { await api.uploadRule(yaml); setSuccess('Rule uploaded!') }
      setTimeout(() => { onSuccess(); onClose() }, 700)
    } catch (e: any) {
      setError(e?.response?.data?.detail ?? 'Operation failed')
    } finally { setLoading(false) }
  }

  const handleFileDrop = async (f: File) => { setYaml(await f.text()); setTab('yaml') }

  const TABS = mode === 'edit'
    ? [{ id: 'fields', label: 'Edit Fields' }, { id: 'yaml', label: 'Edit YAML' }] as const
    : [{ id: 'fields', label: 'Fields' }, { id: 'yaml', label: 'Paste YAML' }, { id: 'file', label: 'Upload File' }] as const

  const lbl = { label: { display: 'block', fontSize: 11, fontWeight: 700, color: 'var(--text-3)', marginBottom: 5, letterSpacing: '0.06em' } }

  return (
    <div style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.6)', backdropFilter: 'blur(4px)', zIndex: 1000, display: 'flex', alignItems: 'center', justifyContent: 'center' }}
      onClick={e => e.target === e.currentTarget && onClose()}>
      <div style={{ background: 'var(--bg-2)', border: '1px solid var(--border)', borderRadius: 12, width: 760, maxWidth: '95vw', maxHeight: '90vh', display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>

        {/* Header */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '14px 18px', borderBottom: '1px solid var(--border)' }}>
          <FileText size={15} color="var(--accent)" />
          <span style={{ fontWeight: 700, fontSize: 14, color: 'var(--text)' }}>{mode === 'edit' ? `Edit - ${rule?.title}` : 'Upload New Rule'}</span>
          <div style={{ flex: 1 }} />
          <button onClick={onClose} style={{ background: 'none', border: 'none', color: 'var(--text-3)', cursor: 'pointer' }}><X size={16} /></button>
        </div>

        {/* Tab bar */}
        <div style={{ display: 'flex', borderBottom: '1px solid var(--border)', padding: '0 18px' }}>
          {TABS.map(t => (
            <button key={t.id} onClick={() => { setTab(t.id as any); setError(''); setSuccess('') }}
              style={{ background: 'none', border: 'none', borderBottom: tab === t.id ? '2px solid var(--accent)' : '2px solid transparent', color: tab === t.id ? 'var(--accent)' : 'var(--text-3)', padding: '8px 14px', cursor: 'pointer', fontSize: 12, fontWeight: tab === t.id ? 600 : 400 }}>
              {t.label}
            </button>
          ))}
        </div>

        {/* Body */}
        <div style={{ flex: 1, overflow: 'auto', padding: 18, display: 'flex', flexDirection: 'column', gap: 14 }}>

          {tab === 'fields' && (
            <>
              {/* UUID */}
              <div>
                <label style={lbl.label}>RULE UUID <span style={{ color: 'var(--text-3)', fontWeight: 400 }}>{mode === 'edit' ? '(read-only)' : '(auto-generated, you can change this)'}</span></label>
                <input readOnly={mode === 'edit'} value={fUuid} onChange={e => setFUuid(e.target.value)} onClick={e => (e.target as HTMLInputElement).select()}
                  style={{ width: '100%', background: mode === 'edit' ? 'var(--bg-3)' : 'var(--bg-2)', border: '1px solid var(--border)', borderRadius: 7, color: mode === 'edit' ? 'var(--text-3)' : 'var(--text)', padding: '8px 12px', fontSize: 12, outline: 'none', fontFamily: 'monospace', cursor: 'text' }} />
              </div>

              {/* Title */}
              <div>
                <label style={lbl.label}>TITLE</label>
                <input value={fTitle} onChange={e => setFTitle(e.target.value)}
                  style={{ width: '100%', background: 'var(--bg-3)', border: '1px solid var(--border)', borderRadius: 7, color: 'var(--text)', padding: '8px 12px', fontSize: 13, outline: 'none' }} />
              </div>

              {/* Severity - pill toggles */}
              <div>
                <label style={lbl.label}>SEVERITY</label>
                <div style={{ display: 'flex', gap: 8 }}>
                  {(['low', 'medium', 'high', 'critical'] as const).map(s => {
                    const m = SEV_META[s]
                    const active = fSeverity === s
                    return (
                      <button key={s} onClick={() => setFSeverity(s)}
                        style={{ flex: 1, padding: '8px 0', borderRadius: 8, border: `2px solid ${active ? m.color : 'var(--border)'}`, background: active ? m.bg : 'var(--bg-3)', color: active ? m.color : 'var(--text-3)', fontWeight: active ? 700 : 500, fontSize: 12, cursor: 'pointer', transition: 'all 0.15s' }}>
                        {s.charAt(0).toUpperCase() + s.slice(1)}
                      </button>
                    )
                  })}
                </div>
              </div>

              {/* MITRE */}
              <div>
                <label style={lbl.label}>MITRE TECHNIQUES <span style={{ color: 'var(--text-3)', fontWeight: 400 }}>(Enter or comma to add, e.g. T1059.001)</span></label>
                <ChipInput values={fMitre} onChange={setFMitre} placeholder="T1059.001" />
              </div>

              {/* Tags */}
              <div>
                <label style={lbl.label}>TAGS <span style={{ color: 'var(--text-3)', fontWeight: 400 }}>(Enter or comma to add, e.g. attack.execution)</span></label>
                <ChipInput values={fTags} onChange={setFTags} placeholder="attack.execution" />
              </div>
            </>
          )}


          {(tab === 'yaml') && (
            <textarea value={yaml} onChange={e => setYaml(e.target.value)} spellCheck={false}
              style={{ width: '100%', flex: 1, minHeight: 380, resize: 'vertical', fontFamily: 'monospace', fontSize: 12, lineHeight: 1.6, background: 'var(--bg-3)', color: 'var(--text)', border: '1px solid var(--border)', borderRadius: 8, padding: 12, outline: 'none' }} />
          )}

          {tab === 'file' && (
            <div onDragOver={e => { e.preventDefault(); setDragging(true) }} onDragLeave={() => setDragging(false)}
              onDrop={async e => { e.preventDefault(); setDragging(false); const f = e.dataTransfer.files[0]; if (f) await handleFileDrop(f) }}
              onClick={() => fileRef.current?.click()}
              style={{ border: `2px dashed ${dragging ? 'var(--accent)' : 'var(--border)'}`, borderRadius: 8, padding: '48px 24px', textAlign: 'center', color: 'var(--text-3)', cursor: 'pointer', flex: 1, minHeight: 380, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', gap: 8 }}>
              <Upload size={28} /><span style={{ fontSize: 13 }}>Drop .yml file or click to browse</span>
              <input ref={fileRef} type="file" accept=".yml,.yaml" style={{ display: 'none' }} onChange={async e => { const f = e.target.files?.[0]; if (f) await handleFileDrop(f) }} />
            </div>
          )}

          {error && <div style={{ color: '#ef4444', fontSize: 12, display: 'flex', gap: 6, alignItems: 'center' }}><AlertCircle size={12} />{error}</div>}
          {success && <div style={{ color: '#22c55e', fontSize: 12, display: 'flex', gap: 6, alignItems: 'center' }}><Check size={12} />{success}</div>}
        </div>

        {/* Footer */}
        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8, padding: '12px 18px', borderTop: '1px solid var(--border)' }}>
          <button onClick={onClose} style={{ padding: '6px 14px', borderRadius: 7, border: '1px solid var(--border)', background: 'none', color: 'var(--text-3)', cursor: 'pointer', fontSize: 12 }}>Cancel</button>
          <button onClick={tab === 'fields' ? submitFields : submitYaml} disabled={loading}
            style={{ padding: '6px 16px', borderRadius: 7, border: 'none', background: loading ? '#6b7280' : 'var(--accent)', color: '#fff', cursor: loading ? 'wait' : 'pointer', fontSize: 12, fontWeight: 600 }}>
            {loading ? 'Saving…' : tab === 'fields' ? 'Save Fields' : mode === 'edit' ? 'Save YAML' : 'Upload Rule'}
          </button>
        </div>
      </div>
    </div>
  )
}

function DeleteModal({ rule, onClose, onConfirm }: { rule: SigmaRule; onClose: () => void; onConfirm: () => void }) {
  return (
    <div style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.6)', backdropFilter: 'blur(4px)', zIndex: 1001, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
      <div style={{ background: 'var(--bg-2)', border: '1px solid var(--border)', borderRadius: 12, padding: 24, width: 380, maxWidth: '90vw' }}>
        <div style={{ display: 'flex', gap: 10, marginBottom: 12 }}><Trash2 size={16} color="#ef4444" /><span style={{ fontWeight: 700, fontSize: 14, color: 'var(--text)' }}>Delete Rule</span></div>
        <p style={{ fontSize: 13, color: 'var(--text-2)', margin: '0 0 16px' }}>Permanently delete <strong>{rule.title}</strong>? This cannot be undone.</p>
        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8 }}>
          <button onClick={onClose} style={{ padding: '6px 14px', borderRadius: 7, border: '1px solid var(--border)', background: 'none', color: 'var(--text-3)', cursor: 'pointer', fontSize: 12 }}>Cancel</button>
          <button onClick={onConfirm} style={{ padding: '7px 16px', borderRadius: 7, border: 'none', background: '#ef4444', cursor: 'pointer', fontSize: 12, fontWeight: 600, color: '#fff' }}>Delete</button>
        </div>
      </div>
    </div>
  )
}

function StatsPanel({ onClose }: { onClose: () => void }) {
  const [stats, setStats] = useState<RuleStat[]>([])
  const [loading, setLoading] = useState(true)
  useEffect(() => { api.getRuleStats().then((d: any) => setStats(d.stats ?? d.rules ?? [])).catch(() => null).finally(() => setLoading(false)) }, [])
  const dead = stats.filter(r => r.is_dead)
  const highNoise = stats.filter(r => r.is_high_noise)

  return (
    <div style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.6)', backdropFilter: 'blur(4px)', zIndex: 1000, display: 'flex', alignItems: 'center', justifyContent: 'center' }}
      onClick={e => e.target === e.currentTarget && onClose()}>
      <div style={{ background: 'var(--bg-2)', border: '1px solid var(--border)', borderRadius: 12, width: 820, maxWidth: '95vw', maxHeight: '88vh', display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '14px 18px', borderBottom: '1px solid var(--border)' }}>
          <BarChart2 size={15} color="var(--accent)" />
          <span style={{ fontWeight: 700, fontSize: 14, color: 'var(--text)' }}>Rule Performance Report</span>
          <div style={{ flex: 1 }} />
          <button onClick={onClose} style={{ background: 'none', border: 'none', color: 'var(--text-3)', cursor: 'pointer' }}><X size={16} /></button>
        </div>
        {loading ? <div style={{ padding: 40, textAlign: 'center', color: 'var(--text-3)' }}>Loading…</div> : (
          <div style={{ overflow: 'auto', padding: 18, display: 'flex', flexDirection: 'column', gap: 20 }}>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3,1fr)', gap: 12 }}>
              {[{ label: 'Total Rules', value: stats.length, color: 'var(--accent)' }, { label: 'Dead Rules', value: dead.length, color: '#ef4444', note: 'enabled, 0 hits' }, { label: 'High Noise', value: highNoise.length, color: '#f97316', note: '>10 hits/day' }].map(c => (
                <div key={c.label} style={{ background: 'var(--bg-3)', borderRadius: 8, padding: '14px 16px', border: '1px solid var(--border)' }}>
                  <div style={{ fontSize: 22, fontWeight: 800, color: c.color }}>{c.value}</div>
                  <div style={{ fontSize: 12, color: 'var(--text-2)', fontWeight: 600 }}>{c.label}</div>
                  {c.note && <div style={{ fontSize: 10, color: 'var(--text-3)', marginTop: 2 }}>{c.note}</div>}
                </div>
              ))}
            </div>
            <div>
              <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-3)', marginBottom: 8, letterSpacing: '0.06em' }}>TOP FIRING RULES</div>
              {stats.filter(r => r.hit_count > 0).slice(0, 5).length === 0
                ? <div style={{ color: 'var(--text-3)', fontSize: 12 }}>No hits recorded yet.</div>
                : stats.filter(r => r.hit_count > 0).slice(0, 5).map((r, i) => (
                  <div key={r.rule_id} style={{ display: 'flex', alignItems: 'center', gap: 10, background: 'var(--bg-3)', borderRadius: 6, padding: '8px 12px', border: '1px solid var(--border)', marginBottom: 4 }}>
                    <span style={{ fontSize: 11, color: 'var(--text-3)', width: 18 }}>#{i + 1}</span>
                    <span style={{ flex: 1, fontSize: 12, color: 'var(--text)', fontWeight: 500 }}>{r.title}</span>
                    <span style={{ fontSize: 12, color: 'var(--accent)', fontWeight: 700 }}>{r.hit_count} hits</span>
                    {r.is_high_noise && <span style={{ fontSize: 9, background: 'rgba(249,115,22,0.15)', color: '#f97316', borderRadius: 4, padding: '1px 6px', fontWeight: 700 }}>HIGH NOISE</span>}
                    <span style={{ fontSize: 10, color: 'var(--text-3)' }}>{r.active_time_str} active</span>
                  </div>
                ))
              }
            </div>
            {dead.length > 0 && (
              <div>
                <div style={{ fontSize: 11, fontWeight: 700, color: '#ef4444', marginBottom: 8 }}>DEAD RULES (enabled, never fired)</div>
                {dead.map(r => (
                  <div key={r.rule_id} style={{ display: 'flex', alignItems: 'center', gap: 10, background: 'rgba(239,68,68,0.05)', borderRadius: 6, padding: '8px 12px', border: '1px solid rgba(239,68,68,0.2)', marginBottom: 4 }}>
                    <span style={{ flex: 1, fontSize: 12, color: 'var(--text)' }}>{r.title}</span>
                    <span style={{ fontSize: 10, color: 'var(--text-3)' }}>{r.active_time_str}, {r.hit_count} hits</span>
                    <span style={{ fontSize: 9, background: SEV_META[r.severity]?.bg ?? 'transparent', color: SEV_META[r.severity]?.color ?? '#6b7280', borderRadius: 4, padding: '1px 6px', fontWeight: 700 }}>{r.severity}</span>
                  </div>
                ))}
              </div>
            )}
            <div>
              <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-3)', marginBottom: 8 }}>ALL RULES</div>
              <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 11 }}>
                <thead><tr>{['Title', 'Severity', 'Uploaded By', 'Hits', 'FP Count', 'Noise/day', 'Active', 'Last Fired'].map(h => (
                  <th key={h} style={{ textAlign: 'left', padding: '6px 8px', color: 'var(--text-3)', fontWeight: 600, borderBottom: '1px solid var(--border)', fontSize: 10 }}>{h.toUpperCase()}</th>
                ))}</tr></thead>
                <tbody>{stats.map(r => (
                  <tr key={r.rule_id}>
                    <td style={{ padding: '7px 8px', color: r.is_new ? '#3b82f6' : 'var(--text)', borderBottom: '1px solid var(--border)' }}>
                      {r.title}
                      {r.is_new && <span style={{ marginLeft: 6, fontSize: 8, background: '#3b82f6', color: '#fff', padding: '1px 4px', borderRadius: 4 }}>NEW</span>}
                    </td>
                    <td style={{ padding: '7px 8px', borderBottom: '1px solid var(--border)' }}><span style={{ background: SEV_META[r.severity]?.bg, color: SEV_META[r.severity]?.color, borderRadius: 4, padding: '1px 6px', fontWeight: 700, fontSize: 10 }}>{r.severity}</span></td>
                    <td style={{ padding: '7px 8px', borderBottom: '1px solid var(--border)', color: 'var(--text-3)', fontSize: 10 }}>{(!r.uploaded_by || r.uploaded_by === 'system') ? 'Admin' : r.uploaded_by}</td>
                    <td style={{ padding: '7px 8px', borderBottom: '1px solid var(--border)', color: 'var(--accent)', fontWeight: 700, whiteSpace: 'nowrap' }}>{r.hit_count}</td>
                    <td style={{ padding: '7px 8px', borderBottom: '1px solid var(--border)', color: r.false_positive_count! > 0 ? 'var(--crit)' : 'var(--text-3)', fontWeight: r.false_positive_count! > 0 ? 700 : 400, whiteSpace: 'nowrap' }}>
                      {r.false_positive_count ?? 0}
                    </td>
                    <td style={{ padding: '7px 8px', borderBottom: '1px solid var(--border)', color: r.is_high_noise ? '#f97316' : 'var(--text-3)' }}>{(r.noise_score || 0).toFixed(2)}</td>
                    <td style={{ padding: '7px 8px', borderBottom: '1px solid var(--border)', color: 'var(--text-3)', whiteSpace: 'nowrap' }}>{r.active_time_str}</td>
                    <td style={{ padding: '7px 8px', borderBottom: '1px solid var(--border)', color: 'var(--text-3)', whiteSpace: 'nowrap' }}>{r.last_fired_at ? new Date(r.last_fired_at * 1000).toLocaleString('en-GB', { day: 'numeric', month: 'numeric', year: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: true }).replace(',', '').toLowerCase().replace(' am', 'am').replace(' pm', 'pm') : '-'}</td>
                  </tr>
                ))}</tbody>
              </table>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

function SqlModal({ rule, onClose }: { rule: SigmaRule; onClose: () => void }) {
  const [sql, setSql] = useState('')
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [copied, setCopied] = useState(false)

  const handleCopy = () => {
    navigator.clipboard.writeText(sql)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  useEffect(() => {
    api.getRuleSql(rule.rule_id)
      .then(res => setSql(res.sql))
      .catch(e => setError(e?.response?.data?.detail ?? 'Failed to compile SQL'))
      .finally(() => setLoading(false))
  }, [rule])

  return (
    <div style={{ position: 'fixed', inset: 0, zIndex: 100, display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 20 }}>
      <div style={{ position: 'absolute', inset: 0, background: 'rgba(0,0,0,0.6)', backdropFilter: 'blur(2px)' }} onClick={onClose} />
      <div style={{ position: 'relative', background: 'var(--bg)', borderRadius: 12, border: '1px solid var(--border)', width: 700, maxWidth: '100%', maxHeight: '90vh', display: 'flex', flexDirection: 'column', boxShadow: '0 20px 40px rgba(0,0,0,0.4)', animation: 'slideUp 0.2s ease-out' }}>
        <div style={{ padding: '16px 20px', borderBottom: '1px solid var(--border)', display: 'flex', alignItems: 'center', justifyContent: 'space-between', background: 'var(--bg-2)', borderRadius: '12px 12px 0 0', flexShrink: 0 }}>
          <div>
            <h3 style={{ margin: 0, fontSize: 16, color: 'var(--text)' }}>Raw SQL Query</h3>
            <p style={{ margin: '4px 0 0 0', fontSize: 12, color: 'var(--text-3)' }}>{rule.title}</p>
          </div>
          <div style={{ display: 'flex', gap: 8 }}>
            {!loading && !error && (
              <button onClick={handleCopy} title="Copy to clipboard" style={{ background: 'var(--bg-3)', border: '1px solid var(--border)', color: copied ? '#10b981' : 'var(--text-3)', padding: '0 10px', height: 28, borderRadius: 6, display: 'flex', alignItems: 'center', gap: 6, cursor: 'pointer', fontSize: 12, fontWeight: 600 }}>
                {copied ? <Check size={14} /> : <Copy size={14} />}
                {copied ? 'Copied' : 'Copy'}
              </button>
            )}
            <button onClick={onClose} style={{ background: 'var(--bg-3)', border: '1px solid var(--border)', color: 'var(--text-3)', width: 28, height: 28, borderRadius: 6, display: 'flex', alignItems: 'center', justifyContent: 'center', cursor: 'pointer' }}>
              <X size={14} />
            </button>
          </div>
        </div>
        <div style={{ padding: 20, background: 'var(--bg-3)', overflowY: 'auto', borderRadius: '0 0 12px 12px' }}>
          {loading ? (
            <div style={{ padding: 40, textAlign: 'center', color: 'var(--text-3)' }}>Compiling YAML to SQL...</div>
          ) : error ? (
            <div style={{ padding: 20, color: 'var(--crit)', background: 'rgba(239,68,68,0.1)' }}>{error}</div>
          ) : (
            <pre style={{ margin: 0, padding: 16, background: '#0d1117', color: '#c9d1d9', borderRadius: 8, fontSize: 13, overflowX: 'auto', border: '1px solid var(--border)', whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
              {sql}
            </pre>
          )}
        </div>
      </div>
    </div>
  )
}

export default function RulesEngine() {
  const [rules, setRules] = useState<SigmaRule[]>([])
  const [loading, setLoading] = useState(true)
  const [refreshing, setRefreshing] = useState(false)
  const [search, setSearch] = useState('')
  const [togglingId, setTogglingId] = useState<string | null>(null)
  const [filter, setFilter] = useState<'all' | 'on' | 'off' | 'custom' | 'global'>('all')
  const [modal, setModal] = useState<{ mode: 'upload' | 'edit'; rule?: SigmaRule } | null>(null)
  const [sqlModalRule, setSqlModalRule] = useState<SigmaRule | null>(null)
  const [deleteTarget, setDeleteTarget] = useState<SigmaRule | null>(null)
  const [showStats, setShowStats] = useState(false)

  const fetchRules = useCallback((silent = false) => {
    if (!silent) setLoading(true); else setRefreshing(true)
    api.getRules().then(d => setRules(d.rules ?? [])).catch(() => null).finally(() => { setLoading(false); setRefreshing(false) })
  }, [])

  useEffect(() => { fetchRules() }, [fetchRules])

  const handleToggle = async (ruleId: string, newEnabled: boolean) => {
    setRules(prev => prev.map(r => r.rule_id === ruleId ? { ...r, enabled: newEnabled } : r))
    setTogglingId(ruleId)
    try { await api.toggleRule(ruleId, newEnabled) }
    catch { setRules(prev => prev.map(r => r.rule_id === ruleId ? { ...r, enabled: !newEnabled } : r)) }
    finally { setTogglingId(null) }
  }

  const handleDelete = async (rule: SigmaRule) => {
    try { await api.deleteRule(rule.rule_id); fetchRules(true) }
    catch (e: any) { alert(e?.response?.data?.detail ?? 'Delete failed') }
    setDeleteTarget(null)
  }

  const enabledCount = rules.filter(r => r.enabled).length
  const customCount = rules.filter(r => r.is_custom).length

  const visible = rules.filter(r => {
    const q = search.toLowerCase()
    const ms = !q || r.title.toLowerCase().includes(q) || r.rule_id.includes(q)
      || (r.technique_ids ?? []).some(t => t.toLowerCase().includes(q))
      || (r.tags ?? []).some(t => t.toLowerCase().includes(q))
    const mf = filter === 'all' || (filter === 'on' && r.enabled) || (filter === 'off' && !r.enabled)
      || (filter === 'custom' && r.is_custom) || (filter === 'global' && r.is_global)
    return ms && mf
  })

  const th = (label: string) => (
    <th key={label} style={{ textAlign: 'left', padding: '9px 12px', fontSize: 10, fontWeight: 700, color: 'var(--text-3)', letterSpacing: '0.06em', borderBottom: '1px solid var(--border)' }}>{label}</th>
  )

  return (
    <div style={{ padding: '18px 20px', display: 'flex', flexDirection: 'column', gap: 12, minHeight: '100%' }}>

      {/* Header bar */}
      <div style={{ background: 'var(--bg-2)', border: '1px solid var(--border)', borderRadius: 10, padding: '10px 14px', display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
        <Shield size={15} color="var(--accent)" />
        <span style={{ fontSize: 14, fontWeight: 700, color: 'var(--text)' }}>Rules Engine</span>
        <span style={{ background: 'rgba(99,102,241,0.1)', color: '#6366f1', borderRadius: 99, padding: '2px 10px', fontSize: 11, fontWeight: 600 }}>{enabledCount} active</span>
        {rules.length - enabledCount > 0 && <span style={{ background: 'var(--bg-3)', border: '1px solid var(--border)', borderRadius: 99, padding: '2px 10px', fontSize: 11, color: 'var(--text-3)' }}>{rules.length - enabledCount} disabled</span>}
        <div style={{ flex: 1 }} />
        {(['all', 'on', 'off', 'global', 'custom'] as const).map(f => (
          <button key={f} onClick={() => setFilter(f)} style={{ border: '1px solid var(--border)', borderRadius: 99, padding: '3px 12px', fontSize: 11, cursor: 'pointer', background: filter === f ? 'var(--accent)' : 'var(--bg-3)', color: filter === f ? '#fff' : 'var(--text-3)', fontWeight: filter === f ? 600 : 400, transition: 'all 0.15s' }}>
            {f === 'all' ? `All (${rules.length})` : f === 'on' ? 'Active' : f === 'off' ? 'Disabled' : f === 'global' ? 'Global' : `Custom (${customCount})`}
          </button>
        ))}
        <div style={{ position: 'relative' }}>
          <Search size={11} style={{ position: 'absolute', left: 9, top: '50%', transform: 'translateY(-50%)', color: 'var(--text-3)' }} />
          <input placeholder="Search title, UUID, author…" value={search} onChange={e => setSearch(e.target.value)} style={{ paddingLeft: 28, paddingRight: 10, paddingTop: 6, paddingBottom: 6, fontSize: 12, width: 220 }} />
        </div>
        <button id="rules-stats-btn" onClick={() => setShowStats(true)} style={{ display: 'flex', alignItems: 'center', gap: 6, border: '1px solid var(--border)', borderRadius: 8, padding: '6px 12px', background: 'var(--bg-3)', cursor: 'pointer', fontSize: 12, color: 'var(--text-2)' }}>
          <BarChart2 size={12} /> Stats
        </button>
        <button id="rules-upload-btn" onClick={() => setModal({ mode: 'upload' })} style={{ display: 'flex', alignItems: 'center', gap: 6, border: 'none', borderRadius: 8, padding: '6px 14px', background: 'var(--accent)', cursor: 'pointer', fontSize: 12, fontWeight: 600, color: '#fff' }}>
          <Upload size={12} /> Upload Rule
        </button>
        <button onClick={() => fetchRules(true)} style={{ background: 'var(--bg-3)', border: '1px solid var(--border)', borderRadius: 8, padding: '6px 8px', cursor: 'pointer', color: 'var(--text-3)' }}>
          <RefreshCw size={12} style={{ animation: refreshing ? 'spin 1s linear infinite' : 'none' }} />
        </button>
      </div>

      {/* Table */}
      <div style={{ background: 'var(--bg-2)', border: '1px solid var(--border)', borderRadius: 10, overflow: 'auto' }}>
        {loading ? (
          <div style={{ padding: 40, textAlign: 'center', color: 'var(--text-3)', fontSize: 13 }}>Loading rules from DB…</div>
        ) : visible.length === 0 ? (
          <div style={{ padding: 40, textAlign: 'center', color: 'var(--text-3)', fontSize: 13 }}>No rules found.</div>
        ) : (
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr style={{ background: 'var(--bg-3)' }}>
                {['TOGGLE', 'RULE', 'SEVERITY', 'MITRE', 'SCOPE', 'UPLOADED BY', 'HITS', 'TAGS', 'ACTIONS'].map(th)}
              </tr>
            </thead>
            <tbody>
              {visible.map(rule => {
                const meta = SEV_META[rule.severity] ?? SEV_META.unknown
                return (
                  <tr key={rule.rule_id}
                    onMouseEnter={e => (e.currentTarget as HTMLElement).style.background = 'var(--bg-3)'}
                    onMouseLeave={e => (e.currentTarget as HTMLElement).style.background = 'transparent'}>

                    {/* Toggle */}
                    <td style={{ padding: '10px 12px', borderBottom: '1px solid var(--border)', width: 60 }}>
                      <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 3 }}>
                        <LiveToggle enabled={rule.enabled} loading={togglingId === rule.rule_id} onChange={v => handleToggle(rule.rule_id, v)} />
                        <span style={{ fontSize: 9, color: rule.enabled ? '#6366f1' : 'var(--text-3)', fontWeight: 600 }}>{rule.enabled ? 'ON' : 'OFF'}</span>
                      </div>
                    </td>

                    {/* Title */}
                    <td style={{ padding: '10px 12px', borderBottom: '1px solid var(--border)', maxWidth: 260 }}>
                      <div style={{ fontWeight: 600, fontSize: 12, color: 'var(--text)', lineHeight: 1.4 }}>
                        {rule.title}
                      </div>
                      <div style={{ fontSize: 10, color: 'var(--text-3)', fontFamily: 'monospace', marginTop: 2 }}>{rule.rule_id.slice(0, 8)}…{rule.rule_id.slice(-4)}</div>
                    </td>

                    {/* Severity */}
                    <td style={{ padding: '10px 12px', borderBottom: '1px solid var(--border)' }}>
                      <span style={{ background: meta.bg, color: meta.color, borderRadius: 99, padding: '3px 10px', fontSize: 11, fontWeight: 700 }}>{meta.label}</span>
                    </td>



                    {/* MITRE */}
                    <td style={{ padding: '10px 12px', borderBottom: '1px solid var(--border)' }}>
                      <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                        {(rule.technique_ids ?? []).slice(0, 3).map(t => (
                          <a key={t} href={`https://attack.mitre.org/techniques/${t.replace('.', '/')}`} target="_blank" rel="noreferrer"
                            style={{ fontSize: 10, background: 'var(--bg-3)', border: '1px solid var(--border)', borderRadius: 4, padding: '1px 6px', color: '#6366f1', fontWeight: 600, fontFamily: 'monospace', textDecoration: 'none' }}>{t}</a>
                        ))}
                        {(rule.technique_ids ?? []).length === 0 && <span style={{ fontSize: 11, color: 'var(--text-3)' }}>-</span>}
                      </div>
                    </td>

                    {/* Scope */}
                    <td style={{ padding: '10px 12px', borderBottom: '1px solid var(--border)' }}>
                      {rule.is_global
                        ? <div style={{ display: 'flex', alignItems: 'center', gap: 5 }}><Globe size={10} color="#22c55e" /><span style={{ fontSize: 10, color: '#22c55e', fontWeight: 600 }}>Global</span></div>
                        : <div style={{ display: 'flex', alignItems: 'center', gap: 5 }}><User size={10} color="#6366f1" /><span style={{ fontSize: 10, color: '#6366f1', fontWeight: 600 }}>User</span></div>
                      }
                    </td>

                    {/* Author */}
                    <td style={{ padding: '10px 12px', borderBottom: '1px solid var(--border)', maxWidth: 110 }}>
                      <span style={{ fontSize: 10, color: 'var(--text-3)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', display: 'block' }}>
                        {(!rule.uploaded_by || rule.uploaded_by === 'system') ? 'Admin' : rule.uploaded_by}
                      </span>
                    </td>

                    {/* Hits + Noise */}
                    <td style={{ padding: '10px 12px', borderBottom: '1px solid var(--border)' }}>
                      <span style={{ fontSize: 12, fontWeight: 700, color: rule.hit_count > 0 ? 'var(--accent)' : 'var(--text-3)', display: 'block' }}>{rule.hit_count}</span>
                    </td>

                    {/* Tags */}
                    <td style={{ padding: '10px 12px', borderBottom: '1px solid var(--border)' }}>
                      <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                        {(rule.tags ?? []).slice(0, 2).map(t => (
                          <span key={t} style={{ fontSize: 9, background: 'var(--bg-3)', border: '1px solid var(--border)', borderRadius: 4, padding: '1px 5px', color: 'var(--text-3)', fontFamily: 'monospace' }}>{t}</span>
                        ))}
                        {(rule.tags ?? []).length === 0 && <span style={{ fontSize: 10, color: 'var(--text-3)' }}>-</span>}
                      </div>
                    </td>

                    {/* Actions */}
                    <td style={{ padding: '10px 12px', borderBottom: '1px solid var(--border)' }}>
                      <div style={{ display: 'flex', gap: 4 }}>
                        <button id={`edit-${rule.rule_id.slice(0, 8)}`} onClick={() => setModal({ mode: 'edit', rule })} title="Edit YAML"
                          style={{ background: 'none', border: '1px solid var(--border)', borderRadius: 6, padding: '4px 6px', cursor: 'pointer', color: 'var(--text-3)', display: 'inline-flex' }}
                          onMouseEnter={e => { (e.currentTarget as HTMLButtonElement).style.borderColor = 'var(--accent)'; (e.currentTarget as HTMLButtonElement).style.color = 'var(--accent)' }}
                          onMouseLeave={e => { (e.currentTarget as HTMLButtonElement).style.borderColor = 'var(--border)'; (e.currentTarget as HTMLButtonElement).style.color = 'var(--text-3)' }}>
                          <Edit2 size={12} />
                        </button>
                        <button onClick={() => setSqlModalRule(rule)} title="View Raw SQL" 
                          style={{ background: 'none', border: '1px solid var(--border)', borderRadius: 6, padding: '4px 6px', cursor: 'pointer', color: 'var(--text-3)', display: 'inline-flex' }}
                          onMouseEnter={e => { (e.currentTarget as HTMLButtonElement).style.borderColor = '#10b981'; (e.currentTarget as HTMLButtonElement).style.color = '#10b981' }}
                          onMouseLeave={e => { (e.currentTarget as HTMLButtonElement).style.borderColor = 'var(--border)'; (e.currentTarget as HTMLButtonElement).style.color = 'var(--text-3)' }}>
                          <Database size={12} />
                        </button>
                        <button id={`del-${rule.rule_id.slice(0, 8)}`} onClick={() => setDeleteTarget(rule)} title="Delete"
                          style={{ background: 'none', border: '1px solid var(--border)', borderRadius: 6, padding: '4px 6px', cursor: 'pointer', color: 'var(--text-3)', display: 'inline-flex' }}
                          onMouseEnter={e => { (e.currentTarget as HTMLButtonElement).style.borderColor = '#ef4444'; (e.currentTarget as HTMLButtonElement).style.color = '#ef4444' }}
                          onMouseLeave={e => { (e.currentTarget as HTMLButtonElement).style.borderColor = 'var(--border)'; (e.currentTarget as HTMLButtonElement).style.color = 'var(--text-3)' }}>
                          <Trash2 size={12} />
                        </button>
                      </div>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        )}
      </div>

      {modal && <YamlModal mode={modal.mode} rule={modal.rule} onClose={() => setModal(null)} onSuccess={() => fetchRules(true)} />}
      {sqlModalRule && <SqlModal rule={sqlModalRule} onClose={() => setSqlModalRule(null)} />}
      {deleteTarget && <DeleteModal rule={deleteTarget} onClose={() => setDeleteTarget(null)} onConfirm={() => handleDelete(deleteTarget)} />}
      {showStats && <StatsPanel onClose={() => setShowStats(false)} />}
    </div>
  )
}
