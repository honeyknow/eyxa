import React, { useState, useEffect } from 'react'
import { api, Alert } from '../api/client'
import { Settings, Play, CheckCircle, AlertTriangle, Loader2, Download } from 'lucide-react'
import ReactMarkdown from 'react-markdown'
import Button from './Button'
import CopyButton from './CopyButton'

interface OmniscientAIProps {
  alert: Alert
}

export default function OmniscientAI({ alert }: OmniscientAIProps) {
  const [activeTab, setActiveTab] = useState<'report' | 'config'>('report')
  const [yamlContent, setYamlContent] = useState('')
  const [apiKey, setApiKey] = useState('')
  const [modelId, setModelId] = useState('llama-3.3-70b-versatile')
  const [sampleRaw, setSampleRaw] = useState('')
  const [sampleEventId, setSampleEventId] = useState<string>('')
  const [isSaving, setIsSaving] = useState(false)
  const [saveSuccess, setSaveSuccess] = useState(false)
  const [showSample, setShowSample] = useState(true)

  const [isAnalyzing, setIsAnalyzing] = useState(false)
  const [report, setReport] = useState<{
    report: string
    raw_event_count: number
    compressed_event_count: number
  } | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    // Unconditionally fetch API key on mount so the empty state knows if one is set
    api.getAiKey().then(res => {
      setApiKey(res.api_key)
      setModelId(res.model_id || 'llama-3.3-70b-versatile')
    }).catch(e => console.error(e))
  }, [])

  // Reset report state when user switches to a different alert
  useEffect(() => {
    setReport(null)
    setError(null)
  }, [alert.alert_id])

  useEffect(() => {
    if (activeTab === 'config' && !yamlContent) {
      api.getAiSchema().then(res => setYamlContent(res.yaml_content)).catch(e => setError(e.message))
    }
  }, [activeTab])

  useEffect(() => {
    if (activeTab === 'config') {
      if (!sampleEventId) {
        setSampleRaw('')
        return
      }
      api.getAiSchemaSample(sampleEventId).then(res => {
        try { setSampleRaw(JSON.stringify(JSON.parse(res.sample), null, 2)) }
        catch { setSampleRaw(res.sample) }
      }).catch(e => console.error("Failed to load sample:", e))
    }
  }, [activeTab, sampleEventId])

  const handleSaveConfig = async () => {
    setIsSaving(true)
    setError(null)
    setSaveSuccess(false)
    try {
      await api.saveAiSchema(yamlContent)
      if (apiKey) await api.saveAiKey(apiKey, modelId)
      setSaveSuccess(true)
      setTimeout(() => setSaveSuccess(false), 2000)
    } catch (e: any) {
      setError(e.response?.data?.detail || e.message)
    } finally {
      setIsSaving(false)
    }
  }

  const handleAnalyze = async () => {
    setActiveTab('report')
    setIsAnalyzing(true)
    setError(null)
    setReport(null)
    try {
      const res = await api.aiInvestigate(alert.alert_id)
      setReport(res)
    } catch (e: any) {
      setError(e.response?.data?.detail || e.message)
    } finally {
      setIsAnalyzing(false)
    }
  }

  const handleDownload = () => {
    if (!report) return
    const blob = new Blob([report.report], { type: 'text/markdown' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `Eyxa_AI_Report_Alert_ID_${alert.alert_id}.md`
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', flex: 1, width: '100%', background: 'var(--bg-2)' }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '12px 16px', borderBottom: '1px solid var(--border)' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <div style={{ background: 'var(--purple)', padding: '6px', borderRadius: '8px', display: 'flex', color: '#000' }}>
            <Play size={16} fill="currentColor" />
          </div>
          <div>
            <h3 style={{ margin: 0, fontSize: 16, color: 'var(--text)' }}>Omniscient AI Engine</h3>
            <p style={{ margin: 0, fontSize: 12, color: 'var(--text-3)' }}>Mathematical Deduplication + Forensics</p>
          </div>
        </div>

        <div style={{ display: 'flex', gap: 8, marginLeft: 'auto' }}>
          <Button variant="ghost" onClick={() => setActiveTab(activeTab === 'config' ? 'report' : 'config')} icon={<Settings size={16} />} style={{ background: activeTab === 'config' ? 'var(--bg-3)' : 'transparent', padding: '8px' }} />
          <Button variant="primary" customColor="var(--purple)" onClick={handleAnalyze} disabled={isAnalyzing}>
            {isAnalyzing ? <><Loader2 size={16} className="spin" /> Analyzing...</> : 'Analyze'}
          </Button>
        </div>
      </div>

      {/* Main Content Area */}
      <div style={{ flex: 1, overflow: 'auto', display: 'flex', flexDirection: 'column' }}>
        {error && activeTab === 'report' && (
          <div style={{ margin: '16px', padding: '12px', background: 'rgba(239, 68, 68, 0.1)', border: '1px solid var(--crit)', borderRadius: 8, color: 'var(--crit)', display: 'flex', alignItems: 'center', gap: 8 }}>
            <AlertTriangle size={16} /> {error}
          </div>
        )}

        {activeTab === 'config' ? (
          <div style={{ padding: '16px', flex: 1, display: 'flex', flexDirection: 'column', gap: 12 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <h4 style={{ margin: 0, color: 'var(--text)' }}>AI Schema Registry (YAML)</h4>
              <div style={{ display: 'flex', gap: 12, alignItems: 'center' }}>
                <select
                  value={modelId}
                  onChange={e => setModelId(e.target.value)}
                  style={{ flex: 1, minWidth: 150, maxWidth: 250, background: '#09090b', border: '1px solid var(--border)', borderRadius: 6, padding: '6px 12px', color: 'var(--text)', fontSize: 12 }}
                >
                  <option value="llama-3.3-70b-versatile">llama-3.3-70b-versatile (12k)</option>
                  <option value="llama-3.1-8b-instant">llama-3.1-8b-instant (6k)</option>
                </select>
                <input 
                  type="password" 
                  placeholder="Groq API Key (gsk_...)" 
                  value={apiKey} 
                  onChange={e => setApiKey(e.target.value)} 
                  style={{ flex: 1, minWidth: 150, maxWidth: 300, background: '#09090b', border: '1px solid var(--border)', borderRadius: 6, padding: '6px 12px', color: 'var(--text)', fontSize: 12 }}
                />
                <Button variant="primary" onClick={handleSaveConfig} disabled={isSaving}>
                  {isSaving ? 'Saving...' : saveSuccess ? <><CheckCircle size={14} /> Saved</> : 'Save Config'}
                </Button>
              </div>
            </div>
            <p style={{ margin: 0, fontSize: 12, color: 'var(--text-3)' }}>Define exactly which JSON keys represent functional behavior for each EventID to mathematically deduplicate events.</p>
            
            <div style={{ display: 'flex', gap: 16, height: 750 }}>
              <div style={{ flex: 1, display: 'flex', flexDirection: 'column', border: '1px solid var(--border)', borderRadius: 8, overflow: 'hidden' }}>
                <div style={{ background: 'var(--bg)', padding: '8px 12px', borderBottom: '1px solid var(--border)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-3)', textTransform: 'uppercase' }}>Deduplication Schema</div>
                  <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                    <Button variant="ghost" onClick={() => setShowSample(!showSample)} style={{ padding: '4px 8px', fontSize: 11, height: 'auto', background: 'var(--bg-2)' }}>
                      {showSample ? 'Hide raw log \u2192' : '\u2190 See raw log by id'}
                    </Button>
                    <CopyButton text={yamlContent} size={14} />
                  </div>
                </div>
                <textarea
                  value={yamlContent}
                  onChange={e => setYamlContent(e.target.value)}
                  style={{ flex: 1, background: '#09090b', color: '#a1a1aa', border: 'none', padding: 16, fontFamily: 'monospace', fontSize: 13, resize: 'none', outline: 'none' }}
                  spellCheck={false}
                />
              </div>

              {showSample && (
                <div style={{ flex: 1, display: 'flex', flexDirection: 'column', border: '1px solid var(--border)', borderRadius: 8, overflow: 'hidden' }}>
                  <div style={{ background: 'var(--bg)', padding: '8px 12px', borderBottom: '1px solid var(--border)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-3)', textTransform: 'uppercase' }}>Sample Raw Sysmon Payload</div>
                    <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                      <input 
                        type="text" 
                        inputMode="numeric"
                        pattern="[0-9]*"
                        placeholder="Event ID (e.g. 1)" 
                        value={sampleEventId}
                        onChange={e => setSampleEventId(e.target.value)}
                        style={{ background: '#09090b', border: '1px solid var(--border)', borderRadius: 4, padding: '2px 6px', color: 'var(--text)', fontSize: 11, width: 100, outline: 'none' }}
                      />
                      <CopyButton text={sampleRaw} size={14} />
                    </div>
                  </div>
                  <div style={{ flex: 1, background: '#09090b', overflow: 'auto', padding: 16 }}>
                    <pre style={{ margin: 0, color: 'var(--text-2)', fontFamily: 'monospace', fontSize: 12 }}>
                      {sampleRaw || "Enter an Event ID above to view a raw sample log."}
                    </pre>
                  </div>
                </div>
              )}
            </div>
          </div>
        ) : (
          <div style={{ padding: '16px', flex: 1 }}>
            {isAnalyzing ? (
              <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', height: '100%', gap: 16, color: 'var(--text-3)' }}>
                <Loader2 size={48} className="spin" color="var(--purple)" />
                <p>Mathematically compressing Blast Radius and consulting AI...</p>
              </div>
            ) : report ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
                <div style={{ display: 'flex', gap: 16 }}>
                  <div style={{
                    background: 'linear-gradient(145deg, rgba(239, 68, 68, 0.1) 0%, rgba(24, 24, 27, 0.5) 100%)',
                    padding: '12px 16px',
                    borderRadius: 12,
                    border: '1px solid rgba(239, 68, 68, 0.2)',
                    flex: 1,
                    display: 'flex',
                    flexDirection: 'column',
                    justifyContent: 'center',
                    boxShadow: '0 4px 20px rgba(0, 0, 0, 0.2), inset 0 1px 0 rgba(255, 255, 255, 0.05)',
                    position: 'relative',
                    overflow: 'hidden'
                  }}>
                    <div style={{ position: 'absolute', top: 0, left: 0, right: 0, height: 2, background: 'linear-gradient(90deg, transparent, var(--crit), transparent)', opacity: 0.5 }} />
                    <div style={{ fontSize: 12, color: 'var(--text-3)', textTransform: 'uppercase', letterSpacing: 1.5, fontWeight: 600, marginBottom: 4 }}>Raw Events Processed</div>
                    <div style={{ fontSize: 28, fontWeight: 800, color: '#fca5a5', textShadow: '0 0 20px rgba(239, 68, 68, 0.4)', fontFamily: 'Inter, sans-serif' }}>
                      {report.raw_event_count.toLocaleString()}
                    </div>
                  </div>
                  
                  <div style={{
                    background: 'linear-gradient(145deg, rgba(168, 85, 247, 0.1) 0%, rgba(24, 24, 27, 0.5) 100%)',
                    padding: '12px 16px',
                    borderRadius: 12,
                    border: '1px solid rgba(168, 85, 247, 0.2)',
                    flex: 1,
                    display: 'flex',
                    flexDirection: 'column',
                    justifyContent: 'center',
                    boxShadow: '0 4px 20px rgba(0, 0, 0, 0.2), inset 0 1px 0 rgba(255, 255, 255, 0.05)',
                    position: 'relative',
                    overflow: 'hidden'
                  }}>
                    <div style={{ position: 'absolute', top: 0, left: 0, right: 0, height: 2, background: 'linear-gradient(90deg, transparent, #a855f7, transparent)', opacity: 0.5 }} />
                    <div style={{ fontSize: 12, color: 'var(--text-3)', textTransform: 'uppercase', letterSpacing: 1.5, fontWeight: 600, marginBottom: 4 }}>Unique Compressed Behaviors</div>
                    <div style={{ fontSize: 28, fontWeight: 800, color: '#d8b4fe', textShadow: '0 0 20px rgba(168, 85, 247, 0.4)', fontFamily: 'Inter, sans-serif' }}>
                      {report.compressed_event_count.toLocaleString()}
                    </div>
                  </div>
                </div>
                
                <div style={{ background: 'var(--bg)', borderRadius: 8, border: '1px solid var(--border)', display: 'flex', flexDirection: 'column' }}>
                  <div style={{ padding: '8px 16px', borderBottom: '1px solid var(--border)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-3)', textTransform: 'uppercase' }}>Forensic Analysis Report</div>
                    <Button variant="ghost" onClick={handleDownload} icon={<Download size={14} />} style={{ fontSize: 12, padding: '4px 8px', height: 'auto', background: 'var(--bg-2)' }}>
                      Download .md
                    </Button>
                  </div>
                  <div className="ai-report-markdown" style={{ padding: '24px', color: 'var(--text-2)', lineHeight: 1.6, fontSize: 14 }}>
                    <ReactMarkdown>{report.report}</ReactMarkdown>
                  </div>
                </div>
              </div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', height: '100%', gap: 16, color: 'var(--text-3)', textAlign: 'center' }}>
                {apiKey ? (
                  <p style={{ margin: 0, fontSize: 14, color: 'var(--text-2)' }}>Ready to analyze. Click <strong style={{ color: 'var(--text)' }}>Analyze</strong> in the top right.</p>
                ) : (
                  <>
                    <AlertTriangle size={32} color="var(--crit)" />
                    <p style={{ margin: 0, fontSize: 14, color: 'var(--text-2)', lineHeight: 1.5, maxWidth: 400 }}>
                      API Key missing! Click the <Settings size={14} style={{ display: 'inline', verticalAlign: 'middle', margin: '0 4px', color: 'var(--text)' }} /> gear icon in the top right to configure your Groq credentials.
                    </p>
                  </>
                )}
              </div>
            )}
          </div>
        )}
      </div>
      
      <style>{`
        .ai-report-markdown h1, .ai-report-markdown h2, .ai-report-markdown h3 { color: var(--text); margin-top: 0; margin-bottom: 16px; border-bottom: 1px solid var(--border); padding-bottom: 8px; }
        .ai-report-markdown p { margin-bottom: 16px; line-height: 1.7; }
        .ai-report-markdown ul, .ai-report-markdown ol { padding-left: 24px; margin-bottom: 16px; }
        .ai-report-markdown li { margin-bottom: 8px; line-height: 1.6; }
        .ai-report-markdown code { background: rgba(168, 85, 247, 0.15); padding: 3px 6px; border-radius: 4px; color: #d8b4fe; font-family: monospace; font-size: 0.9em; border: 1px solid rgba(168, 85, 247, 0.3); }
        .ai-report-markdown pre code { display: block; padding: 16px; background: #09090b; color: var(--text-2); border: 1px solid var(--border); overflow-x: auto; margin-bottom: 16px; }
        .spin { animation: spin 1s linear infinite; }
        @keyframes spin { 100% { transform: rotate(360deg); } }
      `}</style>
    </div>
  )
}
