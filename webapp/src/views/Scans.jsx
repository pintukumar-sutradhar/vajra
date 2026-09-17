import React, { useEffect, useState } from 'react'
import { api } from '../api.js'
import { Modal, Pill, ScanStatus, Spinner, useToast } from '../components.jsx'

const ENGINE = { webapp: 'Web', infrastructure: 'Infra', active_directory: 'AD', external: 'External' }
const TERMINAL = { completed: 1, failed: 1, canceled: 1 }

function fmtSecs(t) {
  const n = Math.max(0, Math.floor(t || 0))
  const h = Math.floor(n / 3600)
  const m = Math.floor((n % 3600) / 60)
  const s = n % 60
  const pad = (x) => String(x).padStart(2, '0')
  return h > 0 ? `${h}:${pad(m)}:${pad(s)}` : `${pad(m)}:${pad(s)}`
}

/* Elapsed excludes time the scan spent paused: the engine was stopped, so
   counting it would overstate how long the work took. */
function workSecs(s) {
  if (!s.started_at) return 0
  const start = new Date(s.started_at).getTime()
  const end = s.finished_at ? new Date(s.finished_at).getTime() : Date.now()
  let secs = (end - start) / 1000 - (s.paused_seconds || 0)
  if (s.paused && s.paused_at) secs -= (Date.now() - new Date(s.paused_at).getTime()) / 1000
  return Math.max(0, secs)
}

export default function Scans({ onOpen }) {
  const [scans, setScans] = useState(null)
  const [, tick] = useState(0)
  const [toDelete, setToDelete] = useState(null)
  const shout = useToast()

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
                  <tr><th>#</th><th>Engine</th><th>Target</th><th>Profile</th><th>Status</th><th>Progress</th><th>Findings</th><th>Refused</th><th>Elapsed</th><th>Started</th><th></th></tr>
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
                        <td>
                          <span style={{ display: 'inline-flex', gap: 6, alignItems: 'center' }}>
                            <ScanStatus value={s.status} />
                            {s.paused && <Pill className="scan-paused">paused</Pill>}
                          </span>
                          {s.verbose > 0 && (
                            <span className="tag" style={{ marginLeft: 6 }}
                              title="Engine verbosity for this run">
                              -{'v'.repeat(s.verbose)}
                            </span>
                          )}
                        </td>
                        <td style={{ minWidth: 110 }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                            <div className={'progress' + (s.paused ? ' tone-paused' : '')}
                              style={{ flex: 1, minWidth: 60 }}>
                              <i style={{ width: pct + '%' }} />
                            </div>
                            <span className="mono muted" style={{ fontSize: 11 }}>{pct}%</span>
                          </div>
                        </td>
                        <td className="muted">{(s.stats && s.stats.findings) || '—'}</td>
                        <td className="muted">{s.suppressed_count || '—'}</td>
                        <td className="mono" style={{ color: running && !s.paused ? 'var(--accent-2)' : 'var(--muted)' }}>
                          {s.started_at ? fmtSecs(workSecs(s)) : '—'}
                        </td>
                        <td className="muted">{new Date(s.created_at).toLocaleString()}</td>
                        <td style={{ textAlign: 'right' }}>
                          {running && (
                            <button className="btn sm" style={{ marginRight: 6 }}
                              title={s.paused ? 'Resume this scan' : 'Pause this scan'}
                              onClick={(e) => {
                                e.stopPropagation()
                                api(`/v1/scans/${s.id}/${s.paused ? 'resume' : 'pause'}`, { method: 'POST' })
                                  .then(load).catch(() => {})
                              }}>{s.paused ? 'Resume' : 'Pause'}</button>
                          )}
                          <button className="btn danger sm" onClick={(e) => { e.stopPropagation(); setToDelete(s) }}>Delete</button>
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            )}
      </div>
      {toDelete && <DeleteScan
        scan={toDelete}
        onClose={() => setToDelete(null)}
        onDone={() => { setToDelete(null); load() }} />}
    </div>
  )
}

function DeleteScan({ scan, onClose, onDone }) {
  const shout = useToast()
  const [busy, setBusy] = useState(false)

  async function del(e) {
    e.preventDefault()
    setBusy(true)
    try {
      await shout.api(() => api(`/v1/scans/${scan.id}`, { method: 'DELETE' }))
      shout.push(`Scan #${scan.id} removed`)
      onDone()
    } catch (err) { setBusy(false) }
  }

  return (
    <Modal title="Delete scan" onClose={onClose}
      foot={<>
        <button className="btn" onClick={onClose}>Cancel</button>
        <button className="btn danger" onClick={del} disabled={busy}>{busy ? 'Deleting…' : `Delete scan #${scan.id}`}</button>
      </>}>
      <p>
        Delete scan <b>#{scan.id}</b> ({scan.engine_id} on {scan.target})?
      </p>
      <p className="muted" style={{ marginTop: 4 }}>
        Its findings, events and run artifacts are removed permanently. This
        cannot be undone.
      </p>
    </Modal>
  )
}