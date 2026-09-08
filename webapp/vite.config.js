import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import http from 'node:http'

const DEFAULT_TARGET = 'http://127.0.0.1:8000'
const CANDIDATE_PORTS = [8000, 8130, 8080]

function httpGetJson(url, timeout = 300) {
  return new Promise((resolve) => {
    const req = http.get(url, { timeout }, (res) => {
      let body = ''
      res.on('data', (c) => { body += c })
      res.on('end', () => { try { resolve(JSON.parse(body)) } catch { resolve(null) } })
    })
    req.on('timeout', () => req.destroy())
    req.on('error', () => resolve(null))
  })
}

async function probeVajra(port) {
  const h = await httpGetJson(`http://127.0.0.1:${port}/health`)
  return !!(h && h.ok === true && h.product === 'VAJRA')
}

async function resolveApiTarget(explicit) {
  if (explicit) return { api: explicit, found: true, auto: false }
  for (const port of CANDIDATE_PORTS) {
    if (await probeVajra(port)) return { api: `http://127.0.0.1:${port}`, found: true, auto: true }
  }
  return { api: DEFAULT_TARGET, found: false, auto: true }
}

export default defineConfig(async ({ command }) => {
  const explicit = process.env.VITE_API_TARGET
  const { api, found, auto } = await resolveApiTarget(explicit)
  const warn = (m) => console.warn('\x1b[33m[VAJRA] ' + m + '\x1b[0m')
  const note = (m) => console.log('\x1b[36m[VAJRA] ' + m + '\x1b[0m')
  if (auto && found) note(`proxying /api → ${api} (auto-detected)`)
  if (auto && !found) warn('no VAJRA API found on ' + CANDIDATE_PORTS.join('/') +
    `. Start it (python server/run_api.py) or set VITE_API_TARGET=http://127.0.0.1:<port> npm run dev`)
  return {
    plugins: [react()],
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
  }
})