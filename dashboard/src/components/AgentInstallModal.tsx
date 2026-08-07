import React, { useEffect, useRef } from 'react'
import { Download, Copy, Terminal, Shield, CheckCircle2 } from 'lucide-react'
import { useToast } from '../context/ToastContext'

interface AgentInstallModalProps {
  isOpen: boolean
  onClose: () => void
  enrollToken: string
  serverIp: string
}

export default function AgentInstallModal({ isOpen, onClose, enrollToken, serverIp }: AgentInstallModalProps) {
  const toast = useToast()
  const modalRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    const handleEscape = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose()
    }
    document.addEventListener('keydown', handleEscape)
    return () => document.removeEventListener('keydown', handleEscape)
  }, [onClose])

  if (!isOpen) return null

  // Auto-detect backend URL. If accessed via localhost, try to use the server's actual LAN IP
  let backendUrl = window.location.origin
  if (backendUrl.includes('localhost') || backendUrl.includes('127.0.0.1')) {
    if (serverIp && serverIp !== '127.0.0.1') {
      backendUrl = backendUrl.replace(/localhost|127\.0\.0\.1/, serverIp)
    }
  }

  const copyToClipboard = (text: string, label: string) => {
    navigator.clipboard.writeText(text)
    toast.success(`Copied ${label} to clipboard`)
  }


  return (
    <div style={{
      position: 'fixed', top: 0, left: 0, right: 0, bottom: 0,
      background: 'rgba(0,0,0,0.8)', backdropFilter: 'blur(4px)',
      display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 9999
    }}>
      <div 
        ref={modalRef}
        className="card"
        style={{
          width: '100%', maxWidth: 700, maxHeight: '90vh', overflowY: 'auto',
          padding: 24, display: 'flex', flexDirection: 'column', gap: 24,
          border: '1px solid var(--border)', boxShadow: '0 20px 40px rgba(0,0,0,0.5)'
        }}
      >
        {/* Header */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
          <div>
            <h2 style={{ fontSize: 20, fontWeight: 800, color: 'var(--text)', display: 'flex', alignItems: 'center', gap: 10 }}>
              <Shield size={24} color="var(--accent)" />
              Enroll New Endpoint
            </h2>
            <p style={{ color: 'var(--text-3)', fontSize: 14, marginTop: 4 }}>
              Install the Eyxa EDR agent on a Windows endpoint to begin streaming telemetry.
            </p>
          </div>
          <button onClick={onClose} style={{ background: 'none', border: 'none', color: 'var(--text-2)', cursor: 'pointer', padding: 4 }}>
            ✕
          </button>
        </div>

        {/* Tokens Section */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          <div style={{ background: 'var(--bg-2)', padding: 16, borderRadius: 8, border: '1px solid var(--border)' }}>
            <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-3)', textTransform: 'uppercase', marginBottom: 6 }}>Your Enrollment Token</div>
            <div style={{ display: 'flex', gap: 12, alignItems: 'center' }}>
              <code style={{ flex: 1, padding: '10px 14px', background: 'var(--bg)', borderRadius: 6, fontSize: 14, color: 'var(--alert-high)', letterSpacing: '1px' }}>
                {enrollToken}
              </code>
              <button onClick={() => copyToClipboard(enrollToken, 'Token')} className="btn btn-secondary">
                <Copy size={16} /> Copy
              </button>
            </div>
          </div>

          <div style={{ background: 'var(--bg-2)', padding: 16, borderRadius: 8, border: '1px solid var(--border)' }}>
            <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-3)', textTransform: 'uppercase', marginBottom: 6 }}>Backend URL</div>
            <div style={{ display: 'flex', gap: 12, alignItems: 'center' }}>
              <code style={{ flex: 1, padding: '10px 14px', background: 'var(--bg)', borderRadius: 6, fontSize: 14, color: 'var(--text)' }}>
                {backendUrl}
              </code>
              <button onClick={() => copyToClipboard(backendUrl, 'URL')} className="btn btn-secondary">
                <Copy size={16} /> Copy
              </button>
            </div>
          </div>
        </div>

        {/* Installation Steps Section */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          {/* Step 1: Exclusions */}
          <div style={{ background: 'var(--bg-2)', padding: 16, borderRadius: 8, border: '1px solid var(--border)' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
              <Terminal size={18} color="var(--accent)" />
              <div style={{ fontSize: 14, fontWeight: 700, color: 'var(--text)' }}>Step 1: Defender Exclusions</div>
            </div>
            <p style={{ color: 'var(--text-3)', fontSize: 13, marginBottom: 12 }}>
              <strong style={{ color: 'var(--alert-high)' }}>IMPORTANT:</strong> Run these commands in an <strong>Administrator PowerShell</strong> before downloading to prevent Windows Defender from quarantining the binaries.
            </p>
            <div style={{ display: 'flex', gap: 12, alignItems: 'center', background: 'var(--bg)', padding: '10px 14px', borderRadius: 6, border: '1px solid var(--border)' }}>
              <pre style={{ flex: 1, margin: 0, fontSize: 13, color: 'var(--alert-high)', whiteSpace: 'pre-wrap', fontFamily: 'monospace' }}>
                mkdir "C:\Program Files\Eyxa" -Force{'\n'}
                mkdir "C:\ProgramData\Eyxa" -Force{'\n'}
                Add-MpPreference -ExclusionPath "C:\Program Files\Eyxa"{'\n'}
                Add-MpPreference -ExclusionPath "C:\ProgramData\Eyxa"
              </pre>
              <button 
                onClick={() => copyToClipboard('mkdir "C:\\Program Files\\Eyxa" -Force\nmkdir "C:\\ProgramData\\Eyxa" -Force\nAdd-MpPreference -ExclusionPath "C:\\Program Files\\Eyxa"\nAdd-MpPreference -ExclusionPath "C:\\ProgramData\\Eyxa"', 'Commands')} 
                className="btn btn-secondary"
              >
                <Copy size={16} /> Copy
              </button>
            </div>
          </div>

          {/* Step 2: Download */}
          <div style={{ background: 'var(--bg-2)', padding: 16, borderRadius: 8, border: '1px solid var(--border)' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
              <Download size={18} color="var(--accent)" />
              <div style={{ fontSize: 14, fontWeight: 700, color: 'var(--text)' }}>Step 2: Download & Install</div>
            </div>
            <p style={{ color: 'var(--text-3)', fontSize: 13, marginBottom: 12 }}>
              Download the ZIP, extract the contents directly into <strong>C:\Program Files\Eyxa</strong>, and run <strong>install.bat</strong> as Administrator.
            </p>
            <a href="/eyxa-agent.zip" download className="btn btn-primary" style={{ alignSelf: 'flex-start', display: 'inline-flex', gap: 8, padding: '10px 20px', fontWeight: 600 }}>
              <Download size={16} /> Download Agent ZIP
            </a>
          </div>
        </div>

        <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: 8 }}>
          <button onClick={onClose} className="btn btn-primary" style={{ padding: '8px 24px' }}>
            Done
          </button>
        </div>
      </div>
    </div>
  )
}
