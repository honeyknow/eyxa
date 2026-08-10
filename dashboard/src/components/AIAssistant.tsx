import React, { useState, useEffect } from 'react'
import { api, Alert } from '../api/client'
import {
  Settings, Play, CheckCircle, AlertTriangle, Loader2, Download,
  ShieldAlert, ShieldCheck, ShieldQuestion, Clock, Target,
  FileText, Globe, Terminal, Database, ChevronRight, Zap,
  Users, Monitor, Lock, Eye, ArrowRight, RefreshCw
} from 'lucide-react'
import Button from './Button'
import CopyButton from './CopyButton'

interface AIAnalysis {
  verdict: 'CONFIRMED_ATTACK' | 'SUSPICIOUS' | 'FALSE_POSITIVE'
  attack_title: string
  urgency: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'
  attack_stage: string
  kill_chain_phase: string
  attacker_objective: string
  mitre_chain: string[]
  similar_techniques: string[]
  timeline: { time: string; event: string; suspicious: boolean }[]
  iocs: { files: string[]; ips: string[]; commands: string[]; registry_keys: string[] }
  raw_ioc_summary: string
  process_chain: string
  affected_users: string[]
  affected_hosts: string[]
  persistence_mechanism: string | null
  evasion_techniques: string[]
  lateral_movement_risk: 'YES' | 'NO' | 'UNKNOWN'
  data_at_risk: string
  analyst_summary: string
  false_positive_reason: string | null
  recommended_actions: string[]
}

interface AIResult {
  analysis: AIAnalysis
  raw_event_count: number
  compressed_event_count: number
  layer1_count: number
  layer2_count: number
  truncated: boolean
  tokens: { prompt: number; completion: number; total: number }
}

interface AIAssistantProps { alert: Alert }

const VERDICT_CONFIG = {
  CONFIRMED_ATTACK: { label: 'CONFIRMED ATTACK', color: '#ef4444', bg: 'rgba(239,68,68,0.12)', border: 'rgba(239,68,68,0.4)', icon: ShieldAlert, glow: '0 0 24px rgba(239,68,68,0.3)' },
  SUSPICIOUS:       { label: 'SUSPICIOUS',        color: '#f59e0b', bg: 'rgba(245,158,11,0.12)', border: 'rgba(245,158,11,0.4)', icon: ShieldQuestion, glow: '0 0 24px rgba(245,158,11,0.3)' },
  FALSE_POSITIVE:   { label: 'FALSE POSITIVE',    color: '#22c55e', bg: 'rgba(34,197,94,0.12)',  border: 'rgba(34,197,94,0.4)',  icon: ShieldCheck, glow: '0 0 24px rgba(34,197,94,0.3)' },
}

const URGENCY_CONFIG = {
  CRITICAL: { color: '#ef4444', bg: 'rgba(239,68,68,0.15)', label: 'CRITICAL' },
  HIGH:     { color: '#f97316', bg: 'rgba(249,115,22,0.15)', label: 'HIGH' },
  MEDIUM:   { color: '#f59e0b', bg: 'rgba(245,158,11,0.15)', label: 'MEDIUM' },
  LOW:      { color: '#22c55e', bg: 'rgba(34,197,94,0.15)',  label: 'LOW' },
}

const LATERAL_CONFIG = {
  YES:     { color: '#ef4444', label: 'YES — Risk Detected' },
  NO:      { color: '#22c55e', label: 'NO — Low Risk' },
  UNKNOWN: { color: '#f59e0b', label: 'UNKNOWN' },
}

export default function AIAssistant({ alert }: AIAssistantProps) {
  const [activeTab, setActiveTab]           = useState<'report' | 'config'>('report')
  const [isLoading, setIsLoading]           = useState(false)
  const [error, setError]                   = useState<string | null>(null)
  const [result, setResult]                 = useState<AIResult | null>(null)
  const [iocTab, setIocTab]                 = useState<'commands' | 'files' | 'ips' | 'registry_keys'>('commands')
  const [apiKey, setApiKey]                 = useState('')
  const [modelId, setModelId]               = useState('openai/gpt-oss-120b')
  const [isSaving, setIsSaving]             = useState(false)
  const [saveSuccess, setSaveSuccess]       = useState(false)
  const [customPrompt, setCustomPrompt]     = useState('')
  const [isCustomPrompt, setIsCustomPrompt] = useState(false)
  const [isSavingPrompt, setIsSavingPrompt] = useState(false)
  const [promptSaved, setPromptSaved]       = useState(false)
  const [yamlContent, setYamlContent]       = useState('')
  const [showSample, setShowSample]         = useState(false)
  const [sampleRaw, setSampleRaw]           = useState('')
  const [sampleEventId, setSampleEventId]   = useState<string>('')

  useEffect(() => { setResult(null); setError(null) }, [alert.alert_id])

  useEffect(() => {
    api.getAiKey().then(cfg => { if (cfg.api_key) setApiKey(cfg.api_key); if (cfg.model_id) setModelId(cfg.model_id) }).catch(() => {})
    api.getAiSchema().then(d => setYamlContent(d.yaml_content)).catch(() => {})
    fetch('/api/config/ai_prompt', { credentials: 'include' })
      .then(r => r.json()).then(d => { setCustomPrompt(d.prompt); setIsCustomPrompt(d.is_custom) }).catch(() => {})
  }, [])

  const handleAnalyze = async () => {
    setIsLoading(true); setError(null)
    try { const data = await api.aiInvestigate(alert.alert_id); setResult(data as AIResult) }
    catch (e: any) { setError(e?.response?.data?.detail || e?.message || 'Unknown error') }
    finally { setIsLoading(false) }
  }

  const handleSaveConfig = async () => {
    setIsSaving(true)
    try { await api.saveAiKey(apiKey, modelId); await api.saveAiSchema(yamlContent); setSaveSuccess(true); setTimeout(() => setSaveSuccess(false), 2000) }
    catch (e) {} finally { setIsSaving(false) }
  }

  const handleSavePrompt = async () => {
    setIsSavingPrompt(true)
    try {
      const r = await fetch('/api/config/ai_prompt', { method: 'POST', credentials: 'include', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ prompt: customPrompt }) })
      const d = await r.json(); setIsCustomPrompt(d.is_custom); setPromptSaved(true); setTimeout(() => setPromptSaved(false), 2000)
    } catch (e) {} finally { setIsSavingPrompt(false) }
  }

  const handleResetPrompt = async () => {
    const r = await fetch('/api/config/ai_prompt/reset', { method: 'POST', credentials: 'include' })
    const d = await r.json(); setCustomPrompt(d.prompt); setIsCustomPrompt(false)
  }

  const handleDownload = () => {
    if (!result?.analysis) return
    const a = result.analysis
    const md = `# Eyxa Forensic Report — Alert #${alert.alert_id}\n## ${a.attack_title}\n**Verdict:** ${a.verdict} | **Urgency:** ${a.urgency}\n**Stage:** ${a.attack_stage} | **Kill Chain:** ${a.kill_chain_phase}\n**Objective:** ${a.attacker_objective}\n\n## MITRE\n${a.mitre_chain.join(', ')}\n\n## Summary\n${a.analyst_summary}\n\n## Process Chain\n${a.process_chain}\n\n## Timeline\n${a.timeline.map(t => `- [${t.time}] ${t.suspicious ? '🔴' : '⚪'} ${t.event}`).join('\n')}\n\n## IOCs\n${a.raw_ioc_summary}\n\n## Actions\n${a.recommended_actions.map((r, i) => `${i + 1}. ${r}`).join('\n')}`
    const blob = new Blob([md], { type: 'text/markdown' }); const url = URL.createObjectURL(blob); const el = document.createElement('a')
    el.href = url; el.download = `Eyxa_Report_Alert_${alert.alert_id}.md`; document.body.appendChild(el); el.click(); document.body.removeChild(el); URL.revokeObjectURL(url)
  }

  const analysis = result?.analysis

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', flex: 1, width: '100%', background: 'var(--bg-2)' }}>
      <style>{`
        .ai-chip { display: inline-flex; align-items: center; gap: 4px; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 700; font-family: monospace; }
        .ai-mitre-badge { display: inline-flex; align-items: center; gap: 4px; padding: 3px 8px; border-radius: 4px; font-size: 11px; font-weight: 700; font-family: monospace; background: rgba(168,85,247,0.15); color: #c084fc; border: 1px solid rgba(168,85,247,0.35); cursor: pointer; transition: all 0.15s; text-decoration: none; }
        .ai-mitre-badge:hover { background: rgba(168,85,247,0.3); }
        .ai-similar-badge { display: inline-flex; align-items: center; padding: 2px 7px; border-radius: 4px; font-size: 10px; font-weight: 600; font-family: monospace; background: rgba(99,102,241,0.12); color: #818cf8; border: 1px solid rgba(99,102,241,0.3); cursor: pointer; text-decoration: none; }
        .ai-similar-badge:hover { background: rgba(99,102,241,0.25); }
        .ai-timeline-dot-red { width: 10px; height: 10px; border-radius: 50%; background: #ef4444; box-shadow: 0 0 8px rgba(239,68,68,0.7); flex-shrink: 0; }
        .ai-timeline-dot-gray { width: 10px; height: 10px; border-radius: 50%; background: var(--bg-5); border: 2px solid var(--border-2); flex-shrink: 0; }
        .ai-ioc-item { font-family: monospace; font-size: 11px; color: var(--text-2); padding: 6px 10px; background: var(--bg); border-radius: 4px; border: 1px solid var(--border); word-break: break-all; display: flex; align-items: flex-start; gap: 8px; }
        .ai-action-item { display: flex; align-items: flex-start; gap: 10px; font-size: 12px; color: var(--text-2); padding: 6px 0; border-bottom: 1px solid var(--border); }
        .ai-action-item:last-child { border-bottom: none; }
        .ai-section-label { font-size: 10px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.08em; color: var(--text-3); margin-bottom: 8px; }
        .ai-ioc-tab { font-size: 11px; font-weight: 600; padding: 4px 10px; border-radius: 4px; cursor: pointer; transition: all 0.15s; border: 1px solid transparent; background: none; }
        .ai-ioc-tab.active { background: rgba(168,85,247,0.2); color: #c084fc; border-color: rgba(168,85,247,0.4); }
        .ai-ioc-tab:not(.active) { color: var(--text-3); }
        .ai-ioc-tab:not(.active):hover { background: var(--bg-3); }
        .ai-tag { display: inline-flex; align-items: center; gap: 4px; padding: 3px 8px; border-radius: 999px; font-size: 11px; font-weight: 600; background: var(--bg-3); border: 1px solid var(--border); color: var(--text-2); }
        .spin { animation: ai-spin 1s linear infinite; }
        @keyframes ai-spin { 100% { transform: rotate(360deg); } }
      `}</style>

      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '8px 12px', borderBottom: '1px solid var(--border)', background: 'var(--bg)', flexShrink: 0 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <Zap size={16} color="#a855f7" />
          <span style={{ fontSize: 13, fontWeight: 700, color: 'var(--text)' }}>AI Forensic Engine</span>
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <Button variant="ghost" onClick={() => setActiveTab(activeTab === 'config' ? 'report' : 'config')} icon={<Settings size={13} />}
            style={{ fontSize: 11, padding: '4px 8px', height: 'auto', background: activeTab === 'config' ? 'var(--bg-3)' : 'transparent' }}>
            Config
          </Button>
          <Button variant="primary" onClick={handleAnalyze} disabled={isLoading}
            icon={isLoading ? <Loader2 size={13} style={{ animation: 'ai-spin 1s linear infinite' }} /> : <Play size={13} />}
            style={{ fontSize: 11, padding: '4px 10px', height: 'auto' }}>
            {isLoading ? 'Analyzing...' : 'Analyze'}
          </Button>
        </div>
      </div>

      {/* Content */}
      <div style={{ flex: 1, overflowY: 'auto', padding: 12 }}>
        {activeTab === 'config' ? (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>

            {/* API Settings */}
            <div style={{ background: 'var(--bg-3)', border: '1px solid var(--border)', borderRadius: 10, padding: '12px 14px' }}>
              <div className="ai-section-label">API Settings</div>
              <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center' }}>
                <select value={modelId} onChange={e => setModelId(e.target.value)}
                  style={{ background: '#09090b', border: '1px solid var(--border)', borderRadius: 6, padding: '6px 10px', color: 'var(--text)', fontSize: 12, minWidth: 300 }}>
                  <option value="openai/gpt-oss-120b">openai/gpt-oss-120b — 8k TPM · 1k RPM (Best quality)</option>
                  <option value="openai/gpt-oss-20b">openai/gpt-oss-20b — 8k TPM · 1k RPM (Fast + accurate)</option>
                  <option value="llama-3.3-70b-versatile">llama-3.3-70b-versatile — 12k TPM · 1k RPM (Highest limit)</option>
                </select>
                <input type="password" placeholder="Groq API Key (gsk_...)" value={apiKey} onChange={e => setApiKey(e.target.value)}
                  style={{ flex: 1, minWidth: 160, background: '#09090b', border: '1px solid var(--border)', borderRadius: 6, padding: '6px 10px', color: 'var(--text)', fontSize: 12 }} />
                <Button variant="primary" onClick={handleSaveConfig} disabled={isSaving}>
                  {isSaving ? 'Saving...' : saveSuccess ? <><CheckCircle size={13} /> Saved</> : 'Save'}
                </Button>
              </div>
            </div>

            {/* System Prompt Editor */}
            <div style={{ background: 'var(--bg-3)', border: '1px solid var(--border)', borderRadius: 10, padding: '12px 14px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
                <div>
                  <div className="ai-section-label" style={{ marginBottom: 2 }}>System Prompt</div>
                  <div style={{ fontSize: 11, color: 'var(--text-3)' }}>
                    Use{' '}
                    {['{rule}', '{technique}', '{severity}', '{telemetry}', '{truncation_note}'].map(p => (
                      <code key={p} style={{ background: 'var(--bg)', padding: '1px 4px', borderRadius: 3, fontSize: 10, marginRight: 4 }}>{p}</code>
                    ))}
                    as placeholders.
                    {isCustomPrompt && <span style={{ marginLeft: 8, color: '#a855f7', fontWeight: 700 }}>• Custom active</span>}
                  </div>
                </div>
                <div style={{ display: 'flex', gap: 6 }}>
                  {isCustomPrompt && (
                    <Button variant="ghost" onClick={handleResetPrompt} icon={<RefreshCw size={11} />}
                      style={{ fontSize: 11, padding: '4px 8px', height: 'auto', color: 'var(--text-3)' }}>
                      Reset to Default
                    </Button>
                  )}
                  <Button variant="primary" onClick={handleSavePrompt} disabled={isSavingPrompt} style={{ fontSize: 11, padding: '4px 10px', height: 'auto' }}>
                    {isSavingPrompt ? 'Saving...' : promptSaved ? <><CheckCircle size={11} /> Saved</> : 'Save Prompt'}
                  </Button>
                </div>
              </div>
              <textarea value={customPrompt} onChange={e => setCustomPrompt(e.target.value)}
                style={{ width: '100%', minHeight: 340, background: '#09090b', border: '1px solid var(--border)', borderRadius: 6, padding: '10px 12px', color: 'var(--text)', fontSize: 11, fontFamily: 'monospace', lineHeight: 1.6, resize: 'vertical', boxSizing: 'border-box' }} />
            </div>

            {/* YAML Schema */}
            <div style={{ background: 'var(--bg-3)', border: '1px solid var(--border)', borderRadius: 10, padding: '12px 14px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
                <div className="ai-section-label" style={{ marginBottom: 0 }}>Deduplication Schema (YAML)</div>
                <Button variant="ghost" onClick={() => setShowSample(!showSample)} style={{ fontSize: 11, padding: '3px 7px', height: 'auto', background: 'var(--bg-2)' }}>
                  {showSample ? 'Hide sample' : 'Show sample'}
                </Button>
              </div>
              <div style={{ display: 'flex', gap: 12 }}>
                <textarea value={yamlContent} onChange={e => setYamlContent(e.target.value)}
                  style={{ flex: 1, minHeight: 200, background: '#09090b', border: '1px solid var(--border)', borderRadius: 6, padding: '8px 10px', color: 'var(--text)', fontSize: 11, fontFamily: 'monospace', resize: 'vertical', boxSizing: 'border-box' }} />
                {showSample && (
                  <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: 6 }}>
                    <div style={{ display: 'flex', gap: 6 }}>
                      <input placeholder="Event ID (optional)" value={sampleEventId} onChange={e => setSampleEventId(e.target.value)}
                        style={{ flex: 1, background: '#09090b', border: '1px solid var(--border)', borderRadius: 6, padding: '5px 8px', color: 'var(--text)', fontSize: 11 }} />
                      <Button variant="ghost" onClick={() => api.getAiSchemaSample(sampleEventId ? parseInt(sampleEventId) : undefined).then(d => setSampleRaw(JSON.stringify(JSON.parse(d.sample), null, 2))).catch(() => {})} style={{ fontSize: 11, padding: '4px 8px', height: 'auto' }}>Load</Button>
                    </div>
                    <pre style={{ flex: 1, background: '#09090b', border: '1px solid var(--border)', borderRadius: 6, padding: '8px 10px', fontSize: 10, fontFamily: 'monospace', color: 'var(--text-2)', overflow: 'auto', margin: 0 }}>
                      {sampleRaw || 'Click Load to fetch a sample event'}
                    </pre>
                  </div>
                )}
              </div>
            </div>
          </div>

        ) : !analysis ? (
          /* Empty / Loading / Error state */
          <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', height: '100%', gap: 12, color: 'var(--text-3)', fontSize: 12 }}>
            {isLoading ? (
              <><Loader2 size={36} style={{ animation: 'ai-spin 1s linear infinite' }} color="#a855f7" /><div style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-2)' }}>Analyzing forensic data...</div></>
            ) : error ? (
              <><AlertTriangle size={32} color="#ef4444" /><div style={{ fontSize: 13, fontWeight: 600, color: '#ef4444' }}>Analysis Failed</div><div style={{ fontSize: 11, maxWidth: 280, textAlign: 'center' }}>{error}</div></>
            ) : (
              <><Zap size={36} color="#a855f7" style={{ opacity: 0.5 }} /><div style={{ textAlign: 'center' }}><div style={{ fontSize: 14, fontWeight: 600, color: 'var(--text-2)', marginBottom: 4 }}>Forensic Engine Ready</div><div style={{ fontSize: 12 }}>Click <strong style={{ color: 'var(--text)' }}>Analyze</strong> to run AI investigation</div></div></>
            )}
          </div>

        ) : (
          /* ── FULL REPORT ── */
          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>

            {/* Hero Row: Verdict + Urgency + Stage/Kill Chain */}
            {(() => {
              const vc = VERDICT_CONFIG[analysis.verdict] || VERDICT_CONFIG.SUSPICIOUS
              const VIcon = vc.icon
              const uc = URGENCY_CONFIG[analysis.urgency] || URGENCY_CONFIG.MEDIUM
              return (
                <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                  <div style={{ flex: '1 1 180px', background: vc.bg, border: `1px solid ${vc.border}`, borderRadius: 10, padding: '12px 14px', display: 'flex', alignItems: 'center', gap: 10, boxShadow: vc.glow }}>
                    <VIcon size={22} color={vc.color} />
                    <div>
                      <div style={{ fontSize: 10, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.1em', color: vc.color, opacity: 0.8 }}>Verdict</div>
                      <div style={{ fontSize: 14, fontWeight: 800, color: vc.color }}>{vc.label}</div>
                    </div>
                  </div>
                  <div style={{ flex: '0 0 auto', background: uc.bg, border: `1px solid ${uc.color}44`, borderRadius: 10, padding: '12px 16px', display: 'flex', flexDirection: 'column', justifyContent: 'center', alignItems: 'center', gap: 2 }}>
                    <div style={{ fontSize: 10, fontWeight: 700, textTransform: 'uppercase', color: uc.color, opacity: 0.8 }}>Urgency</div>
                    <div style={{ fontSize: 18, fontWeight: 900, color: uc.color, fontFamily: 'monospace' }}>{uc.label}</div>
                  </div>
                  <div style={{ flex: '2 1 200px', background: 'var(--bg-3)', border: '1px solid var(--border)', borderRadius: 10, padding: '12px 14px', display: 'flex', flexDirection: 'column', gap: 6 }}>
                    <div>
                      <div style={{ fontSize: 10, fontWeight: 700, textTransform: 'uppercase', color: 'var(--text-3)', marginBottom: 2 }}>Attack Stage</div>
                      <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text)' }}>{analysis.attack_stage}</div>
                    </div>
                    <div>
                      <div style={{ fontSize: 10, fontWeight: 700, textTransform: 'uppercase', color: 'var(--text-3)', marginBottom: 2 }}>Kill Chain Phase</div>
                      <div style={{ fontSize: 12, fontWeight: 600, color: '#a855f7' }}>{analysis.kill_chain_phase}</div>
                    </div>
                  </div>
                </div>
              )
            })()}

            {/* Attack Title + Objective */}
            <div style={{ background: 'var(--bg-3)', border: '1px solid var(--border)', borderRadius: 10, padding: '12px 14px' }}>
              <div style={{ fontSize: 14, fontWeight: 700, color: 'var(--text)', marginBottom: 6 }}>{analysis.attack_title}</div>
              <div style={{ display: 'flex', alignItems: 'flex-start', gap: 6 }}>
                <Target size={13} color="#a855f7" style={{ flexShrink: 0, marginTop: 2 }} />
                <div style={{ fontSize: 12, color: 'var(--text-2)' }}><strong style={{ color: 'var(--text-3)' }}>Objective:</strong> {analysis.attacker_objective}</div>
              </div>
            </div>

            {/* MITRE + Similar Techniques */}
            <div style={{ background: 'var(--bg-3)', border: '1px solid var(--border)', borderRadius: 10, padding: '12px 14px' }}>
              <div className="ai-section-label">MITRE ATT&CK</div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, marginBottom: analysis.similar_techniques?.length > 0 ? 10 : 0 }}>
                {analysis.mitre_chain.map(t => (
                  <a key={t} href={`https://attack.mitre.org/techniques/${t.replace('.', '/')}`} target="_blank" rel="noreferrer" className="ai-mitre-badge">
                    <ChevronRight size={10} />{t}
                  </a>
                ))}
              </div>
              {analysis.similar_techniques?.length > 0 && (
                <>
                  <div style={{ fontSize: 10, fontWeight: 700, textTransform: 'uppercase', color: 'var(--text-3)', marginBottom: 4 }}>Watch Also</div>
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                    {analysis.similar_techniques.map(t => (
                      <a key={t} href={`https://attack.mitre.org/techniques/${t.replace('.', '/')}`} target="_blank" rel="noreferrer" className="ai-similar-badge">{t}</a>
                    ))}
                  </div>
                </>
              )}
            </div>

            {/* Process Chain */}
            {analysis.process_chain && (
              <div style={{ background: 'var(--bg-3)', border: '1px solid var(--border)', borderRadius: 10, padding: '10px 14px' }}>
                <div className="ai-section-label">Process Chain</div>
                <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: 4 }}>
                  {analysis.process_chain.split(/\s*[→>]\s*/).map((p, i, arr) => (
                    <React.Fragment key={i}>
                      <span style={{ fontFamily: 'monospace', fontSize: 12, fontWeight: 600, color: i === arr.length - 1 ? '#ef4444' : 'var(--text)', background: i === arr.length - 1 ? 'rgba(239,68,68,0.1)' : 'var(--bg)', border: `1px solid ${i === arr.length - 1 ? 'rgba(239,68,68,0.3)' : 'var(--border)'}`, padding: '2px 8px', borderRadius: 4 }}>{p.trim()}</span>
                      {i < arr.length - 1 && <ArrowRight size={12} color="var(--text-3)" />}
                    </React.Fragment>
                  ))}
                </div>
              </div>
            )}

            {/* Analyst Summary */}
            <div style={{ background: 'var(--bg-3)', border: '1px solid var(--border)', borderRadius: 10, padding: '12px 14px' }}>
              <div className="ai-section-label">Analyst Summary</div>
              <div style={{ fontSize: 12, color: 'var(--text-2)', lineHeight: 1.7 }}>{analysis.analyst_summary}</div>
              {analysis.false_positive_reason && (
                <div style={{ marginTop: 8, padding: '8px 10px', background: 'rgba(34,197,94,0.08)', border: '1px solid rgba(34,197,94,0.25)', borderRadius: 6, fontSize: 11, color: '#4ade80' }}>
                  <strong>FP Reason:</strong> {analysis.false_positive_reason}
                </div>
              )}
            </div>

            {/* Affected + Risk Grid */}
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
              <div style={{ background: 'var(--bg-3)', border: '1px solid var(--border)', borderRadius: 10, padding: '12px 14px' }}>
                <div className="ai-section-label">Affected</div>
                {analysis.affected_users?.length > 0 && (
                  <div style={{ marginBottom: 8 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 4, marginBottom: 4 }}><Users size={10} color="var(--text-3)" /><span style={{ fontSize: 10, color: 'var(--text-3)', fontWeight: 600 }}>USERS</span></div>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>{analysis.affected_users.map((u, i) => <span key={i} className="ai-tag">{u}</span>)}</div>
                  </div>
                )}
                {analysis.affected_hosts?.length > 0 && (
                  <div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 4, marginBottom: 4 }}><Monitor size={10} color="var(--text-3)" /><span style={{ fontSize: 10, color: 'var(--text-3)', fontWeight: 600 }}>HOSTS</span></div>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>{analysis.affected_hosts.map((h, i) => <span key={i} className="ai-tag">{h}</span>)}</div>
                  </div>
                )}
              </div>
              <div style={{ background: 'var(--bg-3)', border: '1px solid var(--border)', borderRadius: 10, padding: '12px 14px', display: 'flex', flexDirection: 'column', gap: 8 }}>
                <div className="ai-section-label">Risk Indicators</div>
                {(() => {
                  const lm = LATERAL_CONFIG[analysis.lateral_movement_risk] || LATERAL_CONFIG.UNKNOWN
                  return (
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <span style={{ fontSize: 11, color: 'var(--text-3)' }}>Lateral Movement</span>
                      <span style={{ fontSize: 11, fontWeight: 700, color: lm.color, fontFamily: 'monospace' }}>{lm.label}</span>
                    </div>
                  )
                })()}
                <div>
                  <div style={{ fontSize: 10, color: 'var(--text-3)', fontWeight: 600, marginBottom: 2 }}>DATA AT RISK</div>
                  <div style={{ fontSize: 11, color: 'var(--text-2)' }}>{analysis.data_at_risk}</div>
                </div>
                {analysis.persistence_mechanism && (
                  <div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 4, marginBottom: 2 }}><Lock size={10} color="var(--text-3)" /><span style={{ fontSize: 10, color: 'var(--text-3)', fontWeight: 600 }}>PERSISTENCE</span></div>
                    <div style={{ fontSize: 11, color: '#f97316', fontFamily: 'monospace' }}>{analysis.persistence_mechanism}</div>
                  </div>
                )}
                {analysis.evasion_techniques?.length > 0 && (
                  <div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 4, marginBottom: 4 }}><Eye size={10} color="var(--text-3)" /><span style={{ fontSize: 10, color: 'var(--text-3)', fontWeight: 600 }}>EVASION</span></div>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                      {analysis.evasion_techniques.map((e, i) => <span key={i} style={{ fontSize: 10, padding: '2px 6px', background: 'rgba(239,68,68,0.1)', border: '1px solid rgba(239,68,68,0.25)', borderRadius: 3, color: '#f87171', fontFamily: 'monospace' }}>{e}</span>)}
                    </div>
                  </div>
                )}
              </div>
            </div>

            {/* Timeline */}
            {analysis.timeline?.length > 0 && (
              <div style={{ background: 'var(--bg-3)', border: '1px solid var(--border)', borderRadius: 10, padding: '12px 14px' }}>
                <div className="ai-section-label">Timeline</div>
                <div style={{ display: 'flex', flexDirection: 'column' }}>
                  {analysis.timeline.map((t, i) => (
                    <div key={i} style={{ display: 'flex', gap: 10, paddingBottom: i < analysis.timeline.length - 1 ? 10 : 0 }}>
                      <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
                        <div className={t.suspicious ? 'ai-timeline-dot-red' : 'ai-timeline-dot-gray'} style={{ marginTop: 3 }} />
                        {i < analysis.timeline.length - 1 && <div style={{ width: 1, flex: 1, background: 'var(--border)', margin: '3px 0' }} />}
                      </div>
                      <div style={{ paddingBottom: 4 }}>
                        <div style={{ fontSize: 10, fontFamily: 'monospace', color: 'var(--text-3)', marginBottom: 1 }}>{t.time}</div>
                        <div style={{ fontSize: 12, color: t.suspicious ? '#fca5a5' : 'var(--text-2)' }}>{t.event}</div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* IOCs */}
            <div style={{ background: 'var(--bg-3)', border: '1px solid var(--border)', borderRadius: 10, padding: '12px 14px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
                <div className="ai-section-label" style={{ marginBottom: 0 }}>IOCs</div>
                <div style={{ display: 'flex', gap: 4 }}>
                  {(['commands', 'files', 'ips', 'registry_keys'] as const).map(tab => {
                    const count = analysis.iocs[tab]?.length || 0
                    return (
                      <button key={tab} onClick={() => setIocTab(tab)} className={`ai-ioc-tab${iocTab === tab ? ' active' : ''}`}>
                        {tab.replace('_', ' ')}{count > 0 ? ` (${count})` : ''}
                      </button>
                    )
                  })}
                </div>
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                {(analysis.iocs[iocTab] || []).length > 0
                  ? (analysis.iocs[iocTab] || []).map((item, i) => (
                      <div key={i} className="ai-ioc-item">
                        {iocTab === 'commands'      && <Terminal size={11} color="#a855f7" style={{ flexShrink: 0, marginTop: 1 }} />}
                        {iocTab === 'files'         && <FileText size={11} color="#60a5fa" style={{ flexShrink: 0, marginTop: 1 }} />}
                        {iocTab === 'ips'           && <Globe    size={11} color="#34d399" style={{ flexShrink: 0, marginTop: 1 }} />}
                        {iocTab === 'registry_keys' && <Database size={11} color="#f59e0b" style={{ flexShrink: 0, marginTop: 1 }} />}
                        <span style={{ flex: 1 }}>{item}</span>
                        <CopyButton text={item} size={11} />
                      </div>
                    ))
                  : <span style={{ fontSize: 12, color: 'var(--text-3)' }}>No {iocTab.replace('_', ' ')} IOCs identified.</span>
                }
              </div>
              {analysis.raw_ioc_summary && (
                <div style={{ marginTop: 10, padding: '8px 10px', background: 'var(--bg)', border: '1px solid var(--border)', borderRadius: 6, display: 'flex', alignItems: 'flex-start', gap: 8 }}>
                  <div style={{ flex: 1, fontSize: 11, fontFamily: 'monospace', color: 'var(--text-3)', lineHeight: 1.5, wordBreak: 'break-all' }}>{analysis.raw_ioc_summary}</div>
                  <CopyButton text={analysis.raw_ioc_summary} size={11} />
                </div>
              )}
            </div>

            {/* Recommended Actions */}
            {analysis.recommended_actions?.length > 0 && (
              <div style={{ background: 'var(--bg-3)', border: '1px solid var(--border)', borderRadius: 10, padding: '12px 14px' }}>
                <div className="ai-section-label">Recommended Actions</div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                  {analysis.recommended_actions.map((action, i) => (
                    <div key={i} className="ai-action-item">
                      <div style={{ width: 20, height: 20, borderRadius: 4, background: 'rgba(168,85,247,0.2)', border: '1px solid rgba(168,85,247,0.4)', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 10, fontWeight: 700, color: '#c084fc', flexShrink: 0 }}>{i + 1}</div>
                      {action}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Footer */}
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', paddingTop: 4 }}>
              <div style={{ display: 'flex', gap: 10, fontSize: 11, color: 'var(--text-3)', fontFamily: 'monospace', flexWrap: 'wrap' }}>
                {result?.tokens && (
                  <>
                    <span style={{ color: '#a855f7', fontWeight: 700 }}>{result.tokens.total.toLocaleString()} tokens</span>
                    <span>·</span>
                    <span>Sent: {result.tokens.prompt.toLocaleString()}</span>
                    <span>·</span>
                    <span>Received: {result.tokens.completion.toLocaleString()}</span>
                  </>
                )}
                {result?.truncated && <span style={{ color: '#f59e0b' }}>· payload truncated</span>}
              </div>
              <Button variant="ghost" onClick={handleDownload} icon={<Download size={13} />}
                style={{ fontSize: 11, padding: '4px 8px', height: 'auto', background: 'var(--bg-2)' }}>
                Export .md
              </Button>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
