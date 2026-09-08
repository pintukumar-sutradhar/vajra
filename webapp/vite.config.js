import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

const api = process.env.VITE_API_TARGET || 'http://127.0.0.1:8000'

const warnOnWrongTarget = {
  name: 'vajra-target-guard',
  configureServer(server) {
    const msg =
      '\x1b[33m[VAJRA] /api/... is proxied to ' + api +
      '. Is your platform API there?\n  "Not Found"/failed logins usually mean a ' +
      'different service owns that port.\n  Run:\n    VAJRA_API_PORT=<port> python ' +
      'server/run_api.py\n    VITE_API_TARGET=http://127.0.0.1:<port> npm run dev\x1b[0m'
    fetch(api + '/health')
      .then((r) => (r.ok ? r.json() : null))
      .then((h) => {
        if (!h || h.product !== 'VAJRA') console.warn(msg)
      })
      .catch(() => console.warn(msg))
  },
}

export default defineConfig({
  plugins: [react(), warnOnWrongTarget],
  server: {
    port: 5173,
    proxy: {
      '/api': { target: api, changeOrigin: true },
      '/health': { target: api, changeOrigin: true },
    },
  },
  build: {
    outDir: 'dist',
  },
})