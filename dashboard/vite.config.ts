import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// Points to Eyxa backend HTTPS server (port 8443)
const apiTarget = process.env.VITE_API_TARGET || 'https://localhost:8443'
const devPort = Number(process.env.VITE_DEV_PORT || 5173)

export default defineConfig({
  plugins: [react()],
  build: {
    outDir: '../backend/static',
    emptyOutDir: true,
  },
  server: {
    port: devPort,
    proxy: {
      '/health':          { target: apiTarget, changeOrigin: true, secure: false },
      '/stats':           { target: apiTarget, changeOrigin: true, secure: false },
      '/agents':          { target: apiTarget, changeOrigin: true, secure: false },
      '/rules':           { target: apiTarget, changeOrigin: true, secure: false },
      '/alerts':          { target: apiTarget, changeOrigin: true, secure: false },
      '/test':            { target: apiTarget, changeOrigin: true, secure: false },
      '/auth':            { target: apiTarget, changeOrigin: true, secure: false },
      '/admin':           { target: apiTarget, changeOrigin: true, secure: false },
      '/delete-my-data':  { target: apiTarget, changeOrigin: true, secure: false },
      '/hosts':           { target: apiTarget, changeOrigin: true, secure: false },
      '/timeline':        { target: apiTarget, changeOrigin: true, secure: false },
      '/process-tree':    { target: apiTarget, changeOrigin: true, secure: false },
      '/events':          { target: apiTarget, changeOrigin: true, secure: false },
      '/amsi':            { target: apiTarget, changeOrigin: true, secure: false },
      '/download-db':     { target: apiTarget, changeOrigin: true, secure: false },
      '/deploy':          { target: apiTarget, changeOrigin: true, secure: false },
    },
  },
})
