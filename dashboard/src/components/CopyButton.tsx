import React, { useState } from 'react'
import { Copy, Check } from 'lucide-react'

interface CopyButtonProps {
  text: string
  size?: number
  className?: string
  style?: React.CSSProperties
}

export default function CopyButton({ text, size = 14, className = '', style = {} }: CopyButtonProps) {
  const [copied, setCopied] = useState(false)

  const handleCopy = (e: React.MouseEvent) => {
    e.stopPropagation()
    e.preventDefault()
    if (!text) return
    navigator.clipboard.writeText(text)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  return (
    <button
      onClick={handleCopy}
      className={`copy-btn ${className}`}
      style={{
        background: 'transparent',
        border: 'none',
        color: copied ? '#22C55E' : 'var(--text-3)',
        cursor: 'pointer',
        padding: 4,
        display: 'inline-flex',
        alignItems: 'center',
        justifyContent: 'center',
        borderRadius: 4,
        transition: 'all 0.2s ease',
        ...style
      }}
      title="Copy to clipboard"
      onMouseEnter={(e) => e.currentTarget.style.color = copied ? '#22C55E' : 'var(--text)'}
      onMouseLeave={(e) => e.currentTarget.style.color = copied ? '#22C55E' : 'var(--text-3)'}
    >
      {copied ? <Check size={size} /> : <Copy size={size} />}
    </button>
  )
}
