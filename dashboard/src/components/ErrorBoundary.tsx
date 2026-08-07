import { Component, ReactNode } from 'react'

interface Props {
  children: ReactNode
  fallbackTitle?: string
}

interface State {
  hasError: boolean
  error: Error | null
}

export default class ErrorBoundary extends Component<Props, State> {
  state: State = { hasError: false, error: null }

  static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error }
  }

  render() {
    if (this.state.hasError) {
      return (
        <div style={{
          flex: 1, padding: 40, display: 'flex', flexDirection: 'column',
          alignItems: 'center', justifyContent: 'center', color: 'var(--text-2)',
          background: 'var(--bg-1)'
        }}>
          <h2 style={{ color: 'var(--crit)', marginBottom: 8 }}>{this.props.fallbackTitle || 'Component Error'}</h2>
          <pre style={{
            background: 'var(--bg-2)', padding: 16, borderRadius: 8,
            border: '1px solid var(--border)', fontSize: 12, maxWidth: 600, overflow: 'auto'
          }}>
            {this.state.error?.message}
          </pre>
          <button
            onClick={() => this.setState({ hasError: false, error: null })}
            className="btn btn-secondary"
            style={{ marginTop: 16 }}
          >
            Retry
          </button>
        </div>
      )
    }
    return this.props.children
  }
}
