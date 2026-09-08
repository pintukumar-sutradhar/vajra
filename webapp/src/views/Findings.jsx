import React, { useEffect, useMemo, useState } from 'react'
import { api } from '../api.js'
import { Pill, Severity, Confidence, Status, Modal, Empty, Spinner, useToast } from '../components.jsx'

const STATUSES = ['', 'open', 'triaged', 'false-positive', 'accepted-risk', 'fixed']
const NEXT = {
  open: ['triaged', 'false-positive', 'accepted-risk', 'fixed'],
  triaged: ['open', 'false-positive', 'accepted-risk', 'fixed'],
  'false-positive': ['open'],
  'accepted-risk': ['open', 'fixed'],
  fixed: ['open'],
}

export default function Findings() {
  const [rows, setRows] = useState(null)
  const [sev, setSev] = useState('')
  const [status, setStatus] = useState('')
  const [q, setQ] = useState('')
  const [sel, setSel] = useState(null)

  function load() {
    const p = new URLSearchParams()
    if (sev) p.set('severity', sev)
    if (status) p.set('status', status)
    if (q) p.set('q', q)
    api('/v1/findings?' + p.toString()).then(setRows).catch(() => setRows([]))
  }
  useEffect(load, [sev, status, q])

  return (
    <>
      <div className="toolbar">
        <input style={{ maxWidth: 320 }} placeholder="Search title / asset…"
          value={q} onChange={(e) => setQ(e.target.value)} />
        <select value={sev} onChange={(e) => setSev(e.target.value)} style={{ width: 130 }}>
          <option value="">All severities</option>
          {['critical', 'high', 'medium', 'low', 'info'].map((s) => <option key={s}>{s}</option>)}
        </select>
        <select value={status} onChange={(e) => setStatus(e.target.value)} style={{ width: 150 }}>
          <option value="">All statuses</option>
          {STATUSES.slice(1).map((s) => <option key={s}>{s}</option>)}
        </select>
      </div>

      {!rows ? <div className="muted"><Spinner /> loading…</div>
        : rows.length === 0 ? <Empty icon="🛡️" text="No findings match." />
          : (
            <div className="card">
              <table className="vt">
                <thead>
                  <tr><th>Severity</th><th>Title</th><th>Asset</th><th>Status</th><th>Confidence</th><th>Last seen</th></tr>
                </thead>
                <tbody>
                  {rows.map((f) => (
                    <tr key={f.id} style={{ cursor: 'pointer' }} onClick={() => setSel(f)}>
                      <td><Severity value={f.severity} /></td>
                      <td style={{ maxWidth: 460 }}>
                        <div style={{ fontWeight: 600 }}>{f.title}</div>
                        <div className="muted mono" style={{ fontSize: 11.5 }}>{f.ref} · {f.source_module}</div>
                      </td>
                      <td className="mono">{f.asset}</td>
                      <td><Status value={f.status} /></td>
                      <td><Confidence value={f.confidence} /></td>
                      <td className="muted">{new Date(f.last_seen).toLocaleDateString()}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

      {sel && <TriageModal finding={sel} onClose={() => setSel(null)} onChanged={(f) => { setSel(f); load() }} />}
    </>
  )
}

function TriageModal({ finding: f, onClose, onChanged }) {
  const [note, setNote] = useState(f.state_note || '')
  const [status, setStatus] = useState(f.status)
  const [busy, setBusy] = useState(false)
  const [detail, setDetail] = useState(f)
  const shout = useToast()

  useEffect(() => { api('/v1/findings/' + f.id).then(setDetail).catch(() => {}) }, [f.id])

  function transitions() {
    return NEXT[detail.status] || []
  }

  async function save() {
    setBusy(true)
    try {
      const r = await shout.api(() => api('/v1/findings/' + f.id, {
        method: 'PATCH', body: { status, note },
      }))
      onChanged(r)
    } catch (e) { setBusy(false) }
  }

  return (
    <Modal title={`${detail.ref} — ${detail.severity.toUpperCase()}`} onClose={onClose} wide
      foot={<>
        <button className="btn" onClick={() => setStatus(detail.status)} disabled={status === detail.status}>Reset</button>
        <button className="btn" onClick={onClose}>Close</button>
        <button className="btn primary" onClick={save} disabled={busy || status === detail.status && note === (detail.state_note || '')}>
          {busy ? 'Saving…' : 'Save'}
        </button>
      </>}>
      <div style={{ display: 'grid', gridTemplateColumns: 'auto 1fr', gap: '8px 18px', fontSize: 13, marginBottom: 16 }}>
        <span className="muted">Severity</span><span><Severity value={detail.severity} /></span>
        <span className="muted">Confidence</span><span><Confidence value={detail.confidence} /></span>
        <span className="muted">Asset</span><span className="mono">{detail.asset}</span>
        <span className="muted">Category</span><span>{detail.category || '—'}</span>
        <span className="muted">CWE</span><span className="mono">{detail.cwe || '—'}</span>
        <span className="muted">Module</span><span className="mono">{detail.source_module}</span>
      </div>

      <div className="section-title">Title</div>
      <div className="muted" style={{ marginBottom: 12, fontSize: 15, color: 'var(--text)' }}>{detail.title}</div>

      {detail.detail && <>
        <div className="section-title">Detail</div>
        <div className="mono-block" style={{ maxHeight: 180 }}>{detail.detail}</div>
      </>}

      {detail.evidence && detail.evidence.text && <>
        <div className="section-title">Proof of concept / observed evidence</div>
        <div className="mono-block">{detail.evidence.text}</div>
      </>}

      {(detail.evidence && detail.evidence.screenshots || []).length > 0 && <>
        <div className="section-title">PoC screenshots</div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(230px, 1fr))', gap: 10 }}>
          {(detail.evidence.screenshots || []).map((s) => (
            <a key={s} href={'/api/v1/reports/' + detail.scan_id + '/static/' + s}
              target="_blank" rel="noreferrer">
              <img src={'/api/v1/reports/' + detail.scan_id + '/static/' + s}
                alt={s} style={{ width: '100%', border: '1px solid var(--line)', borderRadius: 6 }} />
            </a>
          ))}
        </div>
      </>}

      <div className="field" style={{ marginTop: 16 }}>
        <label>Status</label>
        <select value={status} onChange={(e) => setStatus(e.target.value)}>
          <option value={detail.status}>{detail.status}</option>
          {transitions().map((s) => <option key={s}>{s}</option>)}
        </select>
        <div className="hint">Allowed from current state: {transitions().join(', ') || 'none'}</div>
      </div>

      <div className="field">
        <label>Internal note</label>
        <textarea rows={2} value={note} onChange={(e) => setNote(e.target.value)}
          placeholder="e.g. false positive — split DNS resolver returns 200 for arbitrary vhost" />
      </div>
    </Modal>
  )
}