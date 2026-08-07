import React, { useState, useEffect, useRef } from 'react'
import { Terminal as TerminalIcon, Send, RotateCcw, Copy, Check, ChevronDown, ChevronUp, Trash2, X } from 'lucide-react'
import { api, type Command } from '../api/client'

export default function CommandConsole({ agentId }: { agentId: number }) {
  const [cmdInput, setCmdInput] = useState('')
  const [commands, setCommands] = useState<Command[]>([])
  const [loading, setLoading] = useState(false)
  const scrollContainerRef = useRef<HTMLDivElement>(null)
  const inputRef = useRef<HTMLInputElement>(null)

  const [autoScrollEnabled, setAutoScrollEnabled] = useState(true)

  const fetchCommands = React.useCallback(() => {
    api.getCommands(agentId).then(cmds => setCommands(cmds.reverse())).catch(console.error)
  }, [agentId])

  useEffect(() => {
    fetchCommands()
    const t = setInterval(fetchCommands, 3000)
    return () => clearInterval(t)
  }, [fetchCommands])

  // Scroll to bottom when commands change, but only if auto-scroll is enabled
  useEffect(() => {
    if (autoScrollEnabled && scrollContainerRef.current) {
      scrollContainerRef.current.scrollTop = scrollContainerRef.current.scrollHeight
    }
  }, [commands.length, autoScrollEnabled])

  // Detect manual scrolling up to disable auto-scroll
  const handleScroll = (e: React.UIEvent<HTMLDivElement>) => {
    const target = e.currentTarget
    const isAtBottom = target.scrollHeight - target.scrollTop <= target.clientHeight + 50
    setAutoScrollEnabled(isAtBottom)
  }

  const handleSend = async (e?: React.FormEvent) => {
    e?.preventDefault()
    if (!cmdInput.trim() || loading) return
    setLoading(true)
    try {
      await api.createCommand(agentId, 'run_command', { command: cmdInput.trim() })
      setCmdInput('')
      setAutoScrollEnabled(true)
      
      // Smooth scroll to bottom instantly and focus input
      setTimeout(() => {
        if (scrollContainerRef.current) {
          scrollContainerRef.current.scrollTo({ top: scrollContainerRef.current.scrollHeight, behavior: 'smooth' })
        }
        inputRef.current?.focus()
      }, 50)
      
      fetchCommands()
    } catch (err) {
      console.error(err)
    } finally {
      setLoading(false)
    }
  }

  const handleDeleteQueued = async () => {
    if (!window.confirm('Delete all pending/queued commands for this agent?')) return
    setLoading(true)
    try {
      await api.deleteQueuedCommands(agentId)
      fetchCommands()
    } catch (err) {
      console.error(err)
    } finally {
      setLoading(false)
    }
  }

  const handleDeleteSingleCommand = async (cmdId: number) => {
    if (!window.confirm('Delete this command?')) return
    try {
      await api.deleteCommand(cmdId)
      fetchCommands()
    } catch (err) {
      console.error(err)
    }
  }

  const pendingCount = commands.filter(c => c.status === 'pending').length

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', background: 'var(--bg-2)', borderRadius: 12, border: '1px solid var(--border)', overflow: 'hidden' }}>
      <div style={{ padding: '12px 16px', borderBottom: '1px solid var(--border)', background: 'var(--bg)', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <TerminalIcon size={16} color="var(--accent)" />
          <span style={{ fontSize: 13, fontWeight: 700, color: 'var(--text)' }}>
            Remote Console <span style={{ color: 'var(--text-3)', fontWeight: 500 }}>({commands.length}{pendingCount > 0 ? `, ${pendingCount} pending` : ''})</span>
          </span>
        </div>
      </div>

      <div 
        ref={scrollContainerRef}
        style={{ flex: 1, overflowY: 'auto', padding: 16, display: 'flex', flexDirection: 'column', gap: 12, background: '#09090b', fontFamily: 'monospace' }}
        onScroll={handleScroll}
      >
        {commands.length === 0 ? (
          <div style={{ color: '#52525b', fontSize: 13, fontStyle: 'italic', textAlign: 'center', marginTop: 40 }}>
            No command history. Try running "whoami" or "tasklist".
          </div>
        ) : (
          commands.map(cmd => {
            const payload = (() => { try { return JSON.parse(cmd.payload) } catch { return {} } })()
            const result = (() => { try { return JSON.parse(cmd.result || '{}') } catch { return {} } })()
            
            // Check for explicit error from the agent
            const isError = result.success === false || result.win32_error;
            
            // Decode the Base64 output sent by the C agent
            let outputText = '[No Output]';
            if (result.output_b64) {
              try {
                // Agent sends standard Base64 string from standard pipes (typically ASCII or UTF-8)
                outputText = atob(result.output_b64);
              } catch (e) {
                outputText = '[Error decoding Base64 output]';
              }
            } else if (result.win32_error) {
              outputText = `Command failed. Win32 Error Code: ${result.win32_error}`;
            } else if (result.error) {
              outputText = `Error: ${result.error}`;
            }

            return (
              <div key={cmd.id} style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                <div style={{ color: '#3b82f6', fontSize: 13, fontWeight: 700, display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                  <div>
                    <span style={{ color: '#22c55e' }}>PS C:\&gt;</span> {payload.command || cmd.action}
                  </div>
                  <button
                    onClick={() => handleDeleteSingleCommand(cmd.id)}
                    title="Delete Command"
                    style={{ background: 'transparent', border: 'none', color: 'var(--text-3)', cursor: 'pointer', padding: 2, display: 'flex' }}
                    onMouseOver={e => e.currentTarget.style.color = '#EF4444'}
                    onMouseOut={e => e.currentTarget.style.color = 'var(--text-3)'}
                  >
                    <X size={14} />
                  </button>
                </div>
                {cmd.status === 'pending' || cmd.status === 'sent' ? (
                  <div style={{ color: '#a1a1aa', fontSize: 12 }}>[Executing...]</div>
                ) : (
                  <CollapsibleOutput outputText={outputText} isError={isError} />
                )}
              </div>
            )
          })
        )}
      </div>

      <div style={{ padding: 12, borderTop: '1px solid var(--border)', background: 'var(--bg)', display: 'flex', gap: 8 }}>
        <form onSubmit={handleSend} style={{ flex: 1, display: 'flex', gap: 8 }}>
          <input
            ref={inputRef}
            value={cmdInput}
            onChange={e => setCmdInput(e.target.value)}
            placeholder="Enter command to execute on endpoint..."
            style={{ flex: 1, padding: '8px 12px', fontSize: 13, fontFamily: 'monospace', background: 'var(--bg-3)', border: '1px solid var(--border)', borderRadius: 6, color: 'var(--text)' }}
            disabled={loading}
          />
          <button 
            type="submit" 
            disabled={!cmdInput.trim() || loading}
            style={{ 
              display: 'flex', alignItems: 'center', justifyContent: 'center', width: 36, 
              background: cmdInput.trim() ? 'var(--accent)' : 'var(--bg-3)', 
              color: '#fff', border: 'none', borderRadius: 6, cursor: cmdInput.trim() ? 'pointer' : 'not-allowed',
              transition: 'all 0.15s'
            }}
          >
            <Send size={14} />
          </button>
          <button 
            type="button"
            onClick={handleDeleteQueued} 
            title="Clear Queued Commands" 
            disabled={loading}
            style={{ 
              display: 'flex', alignItems: 'center', justifyContent: 'center', width: 36, 
              background: 'var(--bg-3)', color: '#EF4444', border: '1px solid var(--border)', borderRadius: 6, 
              cursor: loading ? 'not-allowed' : 'pointer', transition: 'all 0.15s', opacity: loading ? 0.5 : 1 
            }}
          >
            <Trash2 size={14} />
          </button>
        </form>
      </div>
    </div>
  )
}

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false)
  return (
    <button 
      onClick={() => {
        navigator.clipboard.writeText(text).catch(() => {})
        setCopied(true)
        setTimeout(() => setCopied(false), 2000)
      }}
      style={{ background: 'var(--bg-3)', border: '1px solid var(--border)', borderRadius: 4, color: copied ? '#22c55e' : '#a1a1aa', cursor: 'pointer', padding: 4, display: 'flex', alignItems: 'center', justifyContent: 'center' }}
      title="Copy Output"
    >
      {copied ? <Check size={14} /> : <Copy size={14} />}
    </button>
  )
}

function CollapsibleOutput({ outputText, isError }: { outputText: string, isError: boolean }) {
  const [expanded, setExpanded] = useState(false)
  const isLong = outputText.split('\n').length > 15 || outputText.length > 1000
  
  const displayValue = (!isLong || expanded) 
    ? outputText 
    : outputText.split('\n').slice(0, 10).join('\n') + '\n\n... (Output truncated, click below to expand) ...'

  return (
    <div style={{ position: 'relative' }}>
      <div style={{ position: 'absolute', top: 8, right: 8, zIndex: 10 }}>
        <CopyButton text={outputText} />
      </div>
      <div style={{ 
        color: isError ? '#ef4444' : '#e4e4e7', 
        fontSize: 13, 
        whiteSpace: 'pre-wrap', 
        background: '#18181b', 
        padding: '12px', 
        borderRadius: 6,
        border: '1px solid #27272a',
        minHeight: 40
      }}>
        {displayValue}
        {isLong && (
          <div style={{ marginTop: 12, borderTop: '1px dashed #3f3f46', paddingTop: 12 }}>
            <button 
              onClick={() => setExpanded(!expanded)} 
              style={{ background: 'transparent', border: 'none', color: '#3b82f6', cursor: 'pointer', fontSize: 12, display: 'flex', alignItems: 'center', gap: 6, padding: 0, fontWeight: 600 }}
            >
              {expanded ? <><ChevronUp size={14} /> Collapse Output</> : <><ChevronDown size={14} /> Expand Full Output ({outputText.split('\n').length} lines)</>}
            </button>
          </div>
        )}
      </div>
    </div>
  )
}
