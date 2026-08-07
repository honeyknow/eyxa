import React from 'react'

export type ButtonVariant = 'primary' | 'secondary' | 'ghost' | 'danger' | 'outline' | 'custom'

export interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant
  size?: 'sm' | 'md' | 'lg'
  icon?: React.ReactNode
  loading?: boolean
  active?: boolean
  customColor?: string
}

export default function Button({
  variant = 'primary',
  size = 'md',
  icon,
  loading = false,
  active = false,
  customColor,
  children,
  className = '',
  disabled,
  style,
  ...props
}: ButtonProps) {
  const classes = ['btn']

  if (variant !== 'custom') {
    classes.push(`btn-${variant}`)
  }

  if (size === 'sm') classes.push('btn-sm')
  if (size === 'lg') classes.push('btn-lg')

  if (active) classes.push('active')
  if (loading) classes.push('loading')

  const customStyle: React.CSSProperties = { ...style }
  if (variant === 'custom' && customColor) {
    customStyle.color = customColor
    customStyle.borderColor = active ? customColor : 'transparent'
    customStyle.background = active ? `color-mix(in srgb, ${customColor} 15%, transparent)` : 'transparent'
  }

  return (
    <button
      className={`${classes.join(' ')} ${className}`.trim()}
      disabled={disabled || loading}
      style={customStyle}
      {...props}
    >
      {loading ? (
        <span className="spinner-sm" />
      ) : icon ? (
        <span className="btn-icon">{icon}</span>
      ) : null}

      {children && <span className="btn-text">{children}</span>}
    </button>
  )
}
