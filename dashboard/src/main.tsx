import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'
import './index.css'
import App from './App.tsx'
import { DashboardProvider } from './context/DashboardContext'
import { ToastProvider } from './context/ToastContext'

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <BrowserRouter>
      <ToastProvider>
        <DashboardProvider>
          <App />
        </DashboardProvider>
      </ToastProvider>
    </BrowserRouter>
  </StrictMode>,
)
