import React, { useEffect, useState } from 'react'
import { api } from '../api.js'
import { ScanStatus, Spinner } from '../components.jsx'

const ENGINE = { webapp: 'Web', infrastructure: 'Infra', active_directory: 'AD', external: 'External' }
const TERMINAL = { completed: 1, failed: 1, canceled: 1 }

function fmtElapsed(start) {
  if (!start) return '—'
  const s = Math.max(0, Date.now() - new Date(start).getTime())
  const t = Math.floor(s / 1000)
  const h = Math.floor(t / 3600)
  const m = Math.floor((t % 3600) / 60)
  const sec = t % 60
  const pad = (n) => String(n).padStart(2, '0')
  return h > 0 ? `${h}:${pad(m)}:${pad(sec)}` : `${pad(m)}:${pad(sec)}`
}

function fmtFixed(start, end) {
  if (!start || !end) return '—'
  const t = Math.floor((new Date(end) - new Date(start)) / 1000)
  const h = Math.floor(t / 3600)
  const m = Math.floor((t % 3600) / 60)
  const sec = t % 60
  const pad = (n) => String(n).padStart(2, '0')
  return h > 0 ? `${h}:${pad(m)}:${pad(sec)}` : `${pad(m)}:${pad(sec)}`
}

export default function Scans({ onOpen }) {
  const [scans, setScans] = useState(null)
  const [, tick] = useState(0)

  function load() {
    api('/v1/scans?limit=50').then(setScans).catch(() => {})
  }
  useEffect(load, [])

  /* Refresh while any scan is live so progress bars move without reloading. */
  useEffect(() => {
    if (!scans) return
    const live = scans.some((s) => !TERMINAL[s.status])
    if (!live) return
    const t = setInterval(load, 4000)
    return () => clearInterval(t)
  }, [scans])

  /* 1s ticker while any scan is running so the elapsed column advances. */
  useEffect(() => {
    if (!scans) return
    const live = scans.some((s) => !TERMINAL[s.status])
    if (!live) return
    const t = setInterval(() => tick((x) => x + 1), 1000)
    return () => clearInterval(t)
  }, [scans])

  return (
    <div>
      <div className="toolbar">
        <div className="muted">Scan queue and history for this workspace.</div>
        <div className="spacer" />
        <button className="btn primary" onClick={() => { window.location.hash = '#/engines' }}>Launch scan</button>
      </div>
      <div className="card">
        {!scans
          ? <div className="muted"><Spinner /> Loading…</div>
          : scans.length === 0
            ? <div className="empty" style={{ padding: 32 }}>No scans yet. Launch one from the Engines page.</div>
            : (
              <table className="vt">
                <thead>
                  <tr><th>#</th><th>Engine</th><th>Target</th><th>Profile</th><th>Status</th><th>Progress</th><th>Findings</th><th>Elapsed</th><th>Started</th></tr>
                </thead>
                <tbody>
                  {scans.map((s) => {
                    const running = !TERMINAL[s.status]
                    const pct = Math.round(s.progress || 0)
                    return (
                      <tr key={s.id} className={running ? 'row-live' : ''}
                        style={{ cursor: 'pointer' }} onClick={() => onOpen(s.id)}>
                        <td className="mono muted">{s.id}</td>
                        <td>{ENGINE[s.engine_id] || s.engine_id}</td>
                        <td>{s.target}</td>
                        <td className="muted">{s.profile}</td>
                        <td><ScanStatus value={s.status} /></td>
                        <td style={{ minWidth: 110 }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                            <div className="progress" style={{ flex: 1, minWidth: 60 }}>
                              <i style={{ width: pct + '%' }} />
                            </div>
                            <span className="mono muted" style={{ fontSize: 11 }}>{pct}%</span>
                          </div>
                        </td>
                        <td className="muted">{(s.stats && s.stats.findings) || '—'}</td>
                        <td className="mono" style={{ color: running ? 'var(--accent-2)' : 'var(--muted)' }}>
                          {running ? fmtElapsed(s.started_at) : fmtFixed(s.started_at || s.created_at, s.finished_at)}
                        </td>
                        <td className="muted">{new Date(s.created_at).toLocaleString()}</td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            )}
      </div>
    </div>
  )
}