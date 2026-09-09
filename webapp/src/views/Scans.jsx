import React, { useEffect, useState } from 'react'
import { api } from '../api.js'
import { ScanStatus } from '../components.jsx'

const ENGINE = { webapp: 'Web', infrastructure: 'Infra', active_directory: 'AD', external: 'External' }

export default function Scans({ onOpen }) {
  const [scans, setScans] = useState(null)

  function load() {
    api('/v1/scans?limit=50').then(setScans).catch(() => {})
  }
  useEffect(load, [])

  // Refresh while any scan is live so progress bars move without reloading.
  useEffect(() => {
    if (!scans) return
    const live = scans.some((s) => !TERMINAL[s.status])
    if (!live) return
    const t = setInterval(load, 4000)
    return () => clearInterval(t)
  }, [scans])

  return (
    <div className="card">
      {!scans
        ? <div className="muted">Loading…</div>
        : scans.length === 0
          ? <div className="empty" style={{ padding: 32 }}>No scans yet. Launch one from the Engines page.</div>
          : (
            <table className="vt">
              <thead>
                <tr><th>#</th><th>Engine</th><th>Target</th><th>Profile</th><th>Status</th><th>Progress</th><th>Findings</th><th>Started</th></tr>
              </thead>
              <tbody>
                {scans.map((s) => (
                  <tr key={s.id} style={{ cursor: 'pointer' }} onClick={() => onOpen(s.id)}>
                    <td className="mono muted">{s.id}</td>
                    <td>{ENGINE[s.engine_id] || s.engine_id}</td>
                    <td>{s.target}</td>
                    <td className="muted">{s.profile}</td>
                    <td><ScanStatus value={s.status} /></td>
                    <td style={{ minWidth: 110 }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                        <div className="progress" style={{ flex: 1, minWidth: 60 }}>
                          <i style={{ width: (s.progress || 0) + '%' }} />
                        </div>
                        <span className="mono muted" style={{ fontSize: 11 }}>{Math.round(s.progress || 0)}%</span>
                      </div>
                    </td>
                    <td className="muted">{(s.stats && s.stats.findings) || '—'}</td>
                    <td className="muted">{new Date(s.created_at).toLocaleString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
    </div>
  )
}

const TERMINAL = { completed: 1, failed: 1, canceled: 1 }