import { createContext, useContext, useCallback, useRef, useState, type ReactNode } from 'react'
import { createPortal } from 'react-dom'
import { CheckCircle2, XCircle, Info, AlertTriangle, X } from 'lucide-react'

type ToastType = 'success' | 'error' | 'info' | 'warning'

interface Toast {
  id: number
  type: ToastType
  title: string
  message?: string
  exiting?: boolean
}

interface ToastContextValue {
  success: (title: string, message?: string) => void
  error:   (title: string, message?: string) => void
  info:    (title: string, message?: string) => void
  warning: (title: string, message?: string) => void
}

const ToastContext = createContext<ToastContextValue>({
  success: () => {}, error: () => {}, info: () => {}, warning: () => {},
})

const ICONS = {
  success: <CheckCircle2 size={16} />,
  error:   <XCircle size={16} />,
  info:    <Info size={16} />,
  warning: <AlertTriangle size={16} />,
}

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([])
  const counterRef = useRef(0)

  const dismiss = useCallback((id: number) => {
    // mark exiting for animation
    setToasts(prev => prev.map(t => t.id === id ? { ...t, exiting: true } : t))
    setTimeout(() => setToasts(prev => prev.filter(t => t.id !== id)), 280)
  }, [])

  const push = useCallback((type: ToastType, title: string, message?: string) => {
    const id = ++counterRef.current
    setToasts(prev => [...prev, { id, type, title, message }])
    setTimeout(() => dismiss(id), 4000)
    return id
  }, [dismiss])

  const api: ToastContextValue = {
    success: (t, m) => push('success', t, m),
    error:   (t, m) => push('error',   t, m),
    info:    (t, m) => push('info',    t, m),
    warning: (t, m) => push('warning', t, m),
  }

  const portal = createPortal(
    <div id="toast-root">
      {toasts.map(toast => (
        <div
          key={toast.id}
          className={`toast toast-${toast.type}${toast.exiting ? ' exiting' : ''}`}
          role="alert"
          aria-live="polite"
        >
          <span style={{ flexShrink: 0, marginTop: 1 }}>{ICONS[toast.type]}</span>
          <div style={{ flex: 1, minWidth: 0 }}>
            <div className="toast-title">{toast.title}</div>
            {toast.message && <div className="toast-message">{toast.message}</div>}
          </div>
          <button className="toast-close" onClick={() => dismiss(toast.id)} aria-label="Dismiss">
            <X size={14} />
          </button>
        </div>
      ))}
    </div>,
    document.body
  )

  return (
    <ToastContext.Provider value={api}>
      {children}
      {portal}
    </ToastContext.Provider>
  )
}

export function useToast() {
  return useContext(ToastContext)
}
