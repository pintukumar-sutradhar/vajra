import React, { useEffect, useMemo, useState } from 'react'
import { api } from '../api.js'
import {
  Severity, Confidence, Status, Empty, Spinner, Modal, useToast,
} from '../components.jsx'
import { IcoShield, IcoDoc } from '../icons.jsx'

const COLUMNS = ['new', 'triaged', 'confirmed', 'remediated', 'wont_fix']
const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info']
const STATUSES = ['open', 'triaged', 'false-positive', 'accepted-risk', 'fixed']

export default function Findings() {
  const [rows, setRows] = useState(null)
  const [sev, setSev] = useState('')
  const [status, setStatus] = useState('')
  const [q, setQ] = useState('')
  const [mod, setMod] = useState('')
  const [conf, setConf] = useState('')
  const [sort, setSort] = useState('risk')
  const [hideInfo, setHideInfo] = useState(true)
  const [view, setView] = useState('table')
  const [sel, setSel] = useState(null)
  const [picked, setPicked] = useState(new Set())
  const [users, setUsers] = useState([])
  const shout = useToast()

  function load() {
    const p = new URLSearchParams()
    if (sev) p.set('severity', sev)
    if (status) p.set('status', status)
    if (mod) p.set('engine_id', mod)
    if (q) p.set('q', q)
    if (sort) p.set('sort', sort)
    api('/v1/findings?' + p.toString()).then(setRows).catch(() => setRows([]))
  }
  useEffect(load, [sev, status, mod, q, sort])
  useEffect(() => { api('/v1/auth/users').then(setUsers).catch(() => setUsers([])) }, [])

  const filtered = useMemo(() => {
    if (!rows) return null
    let out = rows
    if (hideInfo) out = out.filter((f) => (f.severity || 'info').toLowerCase() !== 'info')
    if (conf) out = out.filter((f) => (f.confidence || '') === conf)
    return out
  }, [rows, hideInfo, conf])

  const byCount = useMemo(() => {
    const c = { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 }
    ;(rows || []).forEach((f) => {
      const k = (f.severity || 'info').toLowerCase()
      if (k in c) c[k] += 1
      c.total += 1
    })
    return c
  }, [rows])

  const kanban = useMemo(() => {
    const buckets = {}
    COLUMNS.forEach((c) => buckets[c] = [])
    if (!filtered) return buckets
    filtered.forEach((f) => {
      const col = COLUMNS.includes(f.status) ? f.status : 'new'
      buckets[col].push(f)
    })
    return buckets
  }, [filtered])

  async function quickTriage(f, nextStatus, note) {
    try {
      await shout.api(() => api('/v1/findings/' + f.id, {
        method: 'PATCH', body: { status: nextStatus, note: note || f.state_note || '' },
      }))
      load()
    } catch (e) { /* toast shows error */ }
  }

  async function recheck(f) {
    try {
      const r = await shout.api(() => api('/v1/findings/' + f.id + '/recheck', { method: 'POST', body: {} }))
      shout.push('Re-verify scan #' + r.scan_id + ' queued — it re-probes only ' + r.module, 'ok')
      load()
    } catch (e) { /* toast */ }
  }

  function togglePick(id) {
    setPicked((prev) => {
      const n = new Set(prev)
      if (n.has(id)) n.delete(id)
      else n.add(id)
      return n
    })
  }

  async function bulkSet(nextStatus) {
    if (picked.size === 0) return
    try {
      const r = await shout.api(() => api('/v1/findings/bulk', {
        method: 'POST', body: { ids: [...picked], status: nextStatus } }))
      shout.push(r.changed + ' finding(s) updated', 'ok')
      setPicked(new Set())
      load()
    } catch (e) { /* toast */ }
  }

  const selAll = !!filtered && filtered.length > 0
    && filtered.every((f) => picked.has(f.id))

  function RiskBar({ value }) {
    const v = Math.max(0, Math.min(10, value || 0))
    const color = v >= 8 ? '#be183c' : v >= 6 ? '#d97706' : v >= 4 ? '#ca8a04' : v >= 2 ? '#2563eb' : '#475569'
    return (
      <span className="riskchip" style={{ color }}>
        <i style={{ width: 44, height: 5, background: 'color-mix(in srgb, ' + color + ' 22%, transparent)', borderRadius: 3, display: 'inline-block', position: 'relative', top: -1 }}>
          <b style={{ display: 'block', width: (v / 10) * 44, height: 5, background: color, borderRadius: 3 }} />
        </i>
        <b style={{ width: 26, textAlign: 'right' }}>{v.toFixed(1)}</b>
      </span>
    )
  }

  function renderTable() {
    if (!filtered) return <div className="muted"><Spinner /> loading…</div>
    if (filtered.length === 0) return <Empty text="No findings match your filters." />
    return (
      <div className="card">
        <table className="vt">
          <thead>
            <tr>
              <th style={{ width: 30 }}><input type="checkbox" checked={selAll}
                onChange={(e) => setPicked(e.target.checked
                  ? new Set(filtered.map((f) => f.id)) : new Set())} /></th>
              <th>Severity</th><th>Title</th><th>Asset</th><th>Status</th><th>Risk</th>
              <th>Due</th><th>Re-check</th><th></th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((f) => (
              <tr key={f.id} style={{ cursor: 'pointer' }} onClick={() => setSel(f)}>
                <td onClick={(e) => e.stopPropagation()}>
                  <input type="checkbox" checked={picked.has(f.id)}
                    onChange={() => togglePick(f.id)} />
                </td>
                <td><Severity value={f.severity} /></td>
                <td style={{ maxWidth: 380 }}>
                  <div style={{ fontWeight: 600 }}>{f.title}</div>
                  <div className="muted mono" style={{ fontSize: 11.5 }}>{f.ref} · {f.source_module}</div>
                </td>
                <td className="mono">{f.asset}</td>
                <td><Status value={f.status} /></td>
                <td><RiskBar value={f.risk} /></td>
                <td className="muted" style={{ fontSize: 12 }}>
                  {f.due_date ? new Date(f.due_date).toLocaleDateString() : '—'}
                </td>
                <td onClick={(e) => e.stopPropagation()}>
                  <button className="btn sm"
                    title="Re-probe this exact vector and auto-fix if it no longer reproduces"
                    onClick={(e) => { e.stopPropagation(); recheck(f) }}>
                    Re-verify
                  </button>
                </td>
                <td onClick={(e) => e.stopPropagation()}>
                  {f.status !== 'false-positive' && (
                    <button className="btn sm"
                      title="Mark as false positive"
                      onClick={(e) => { e.stopPropagation(); quickTriage(f, 'false-positive', 'False positive — quick triage from findings list.') }}>
                      Mark FP
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    )
  }

  function renderKanban() {
    if (!filtered) return <div className="muted"><Spinner /> loading…</div>
    return (
      <div className="grid" style={{ gridTemplateColumns: 'repeat(5, 1fr)', gap: 16 }}>
        {COLUMNS.map((c) => (
          <div key={c} className="card" style={{ minHeight: 400, display: 'flex', flexDirection: 'column' }}>
            <div style={{ fontWeight: 600, marginBottom: 10, textTransform: 'uppercase', fontSize: 12, color: 'var(--muted)' }}>
              {c} <span className="muted mono">({kanban[c]?.length || 0})</span>
            </div>
            <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: 8 }}>
              {(kanban[c] || []).length === 0
                ? <div className="muted" style={{ textAlign: 'center', marginTop: 20 }}>—</div>
                : (kanban[c] || []).map((f) => (
                  <div key={f.id} className="card" style={{ cursor: 'pointer', padding: 12, fontSize: 12.5 }}
                    onClick={() => setSel(f)}>
                    <div style={{ display: 'flex', gap: 8, alignItems: 'flex-start', marginBottom: 6 }}>
                      <Severity value={f.severity} />
                      <div style={{ flex: 1 }}>
                        <div style={{ fontWeight: 600, fontSize: 13 }}>{f.title}</div>
                        <div className="muted mono" style={{ fontSize: 11 }}>{f.ref} · {f.source_module}</div>
                      </div>
                      <b className="muted" style={{ fontSize: 11 }}>{(f.risk || 0).toFixed(1)}</b>
                    </div>
                    <div className="muted mono" style={{ fontSize: 11 }}>{f.asset}</div>
                  </div>
                ))}
            </div>
          </div>
        ))}
      </div>
    )
  }

  const queryStatus = status ? '&status=' + encodeURIComponent(status) : ''

  return (
    <>
      <div className="toolbar">
        <input style={{ maxWidth: 220 }} placeholder="Search title / asset / detail…"
          value={q} onChange={(e) => setQ(e.target.value)} />
        <select value={sev} onChange={(e) => setSev(e.target.value)} style={{ width: 130 }}>
          <option value="">All severities</option>
          {SEV_ORDER.map((s) => <option key={s}>{s}</option>)}
        </select>
        <select value={status} onChange={(e) => setStatus(e.target.value)} style={{ width: 150 }}>
          <option value="">All statuses</option>
          {STATUSES.map((s) => <option key={s}>{s}</option>)}
        </select>
        <select value={conf} onChange={(e) => setConf(e.target.value)} style={{ width: 130 }}>
          <option value="">All confidence</option>
          {['certain', 'firm', 'tentative'].map((s) => <option key={s}>{s}</option>)}
        </select>
        <select value={mod} onChange={(e) => setMod(e.target.value)} style={{ width: 130 }}>
          <option value="">All engines</option>
          {['webapp', 'infrastructure', 'api', 'external'].map((m) => <option key={m}>{m}</option>)}
        </select>
        <select value={sort} onChange={(e) => setSort(e.target.value)} style={{ width: 130 }}>
          <option value="risk">Sort by risk</option>
          <option value="severity">Sort by severity</option>
          <option value="newest">Newest first</option>
          <option value="last_seen">Last seen</option>
        </select>
        <label className="switch" title="Hide informational observations from the list">
          <input type="checkbox" checked={hideInfo} onChange={(e) => setHideInfo(e.target.checked)} />
          <span className="slider" />
          <span className="switch-label">Hide info</span>
        </label>
        <div className="spacer" />
        <a className="btn" title="Consolidated HTML report across every target" target="_blank"
          rel="noreferrer" href={'/api/v1/reports/consolidated/html?download=1' + queryStatus}>
          <IcoDoc /> HTML</a>
        <a className="btn" title="Consolidated PDF report across every target" target="_blank"
          rel="noreferrer" href={'/api/v1/reports/consolidated/pdf' + queryStatus}>
          <IcoDoc style={{ transform: 'rotate(90deg)' }} /> PDF</a>
        <span className="chip">found {byCount.total}</span>
        <div style={{ display: 'flex', gap: 6 }}>
          <button className="btn" onClick={() => setView('table')} disabled={view === 'table'}>Table</button>
          <button className="btn" onClick={() => setView('kanban')} disabled={view === 'kanban'}>Kanban</button>
        </div>
      </div>

      <div className="sev-summary">
        {SEV_ORDER.map((s) => (
          <span key={s} className={'sev-sum ' + s}>
            <i style={{ background: 'var(--sev-' + s + ')' }} />
            {s} <b>{byCount[s]}</b>
          </span>
        ))}
      </div>

      {picked.size > 0 && (
        <div className="bulkbar">
          <b>{picked.size} selected</b>
          <select value="" onChange={(e) => { if (e.target.value) bulkSet(e.target.value); e.target.value = '' }} style={{ width: 180 }}>
            <option value="">Move to…</option>
            {STATUSES.map((s) => <option key={s}>{s}</option>)}
          </select>
          <button className="btn sm" onClick={() => setPicked(new Set())}>Clear</button>
        </div>
      )}

      {view === 'table' ? renderTable() : renderKanban()}

      {sel && <TriageModal finding={sel} users={users}
        onClose={() => setSel(null)}
        onChanged={(f) => { setSel(f); load() }}
        onRecheck={(f) => { setSel(null); recheck(f) }} />}
    </>
  )
}

function TriageModal({ finding: f, users, onClose, onChanged, onRecheck }) {
  const [note, setNote] = useState(f.state_note || '')
  const [status, setStatus] = useState(f.status)
  const [assigneeId, setAssigneeId] = useState(f.assignee_id || 0)
  const [dueDate, setDueDate] = useState(f.due_date ? f.due_date.slice(0, 10) : '')
  const [busy, setBusy] = useState(false)
  const [detail, setDetail] = useState(f)
  const shout = useToast()

  useEffect(() => { api('/v1/findings/' + f.id).then(setDetail).catch(() => {}) }, [f.id])

  const NEXT = {
    open: ['triaged', 'false-positive', 'accepted-risk', 'fixed'],
    triaged: ['open', 'false-positive', 'accepted-risk', 'fixed'],
    'false-positive': ['open'],
    'accepted-risk': ['open', 'fixed'],
    fixed: ['open'],
  }
  function transitions() { return NEXT[detail.status] || [] }

  async function save() {
    setBusy(true)
    try {
      const r = await shout.api(() => api('/v1/findings/' + f.id, {
        method: 'PATCH', body: {
          status, note,
          assignee_id: assigneeId ? assigneeId : null,
          due_date: dueDate || undefined,
        },
      }))
      onChanged(r)
    } catch (e) { setBusy(false) }
  }

  return (
    <Modal title={`${detail.ref} — ${(detail.severity || 'info').toUpperCase()}`} onClose={onClose} wide
      foot={<>
        <button className="btn" onClick={() => onRecheck(detail)}
          title="Re-probe this exact vector; auto-fixes if it no longer reproduces">
          Re-verify</button>
        <button className="btn" onClick={() => setStatus(detail.status)} disabled={status === detail.status}>Reset</button>
        <button className="btn" onClick={onClose}>Close</button>
        <button className="btn primary" onClick={save} disabled={busy}>
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
        <span className="muted">Evidence risk</span>
        <span><b>{(detail.risk || 0).toFixed(1)} / 10</b>
          <span className="muted" style={{ fontSize: 11.5 }}>  (severity × confidence, lifted by proof ceiling)</span></span>
      </div>

      {/* Lead with the proof. Everything below it is context; this is the
          reason to believe the finding exists at all. */}
      {detail.proof && (
        <div className="proofbox">
          <IcoShield />
          <div>
            <div className="proof-lbl">What proves this</div>
            <div className="proof-txt mono">{detail.proof}</div>
          </div>
        </div>
      )}

      {detail.recheck_outcome && (
        <div className="proofbox" style={{ borderColor: detail.recheck_outcome === 'fixed' ? 'var(--sev-low, #2563eb)' : 'var(--sev-high, #d97706)' }}>
          <IcoShield />
          <div>
            <div className="proof-lbl">Last re-verification</div>
            <div className="proof-txt mono">
              {detail.recheck_outcome === 'reproduced' ? 'Still reproducible' : 'No longer reproduced — fixed'}
              {detail.rechecked_at ? ' · ' + new Date(detail.rechecked_at).toLocaleString() : ''}
            </div>
          </div>
        </div>
      )}

      <div className="section-title">Title</div>
      <div style={{ marginBottom: 12, fontSize: 15, color: 'var(--text)' }}>{detail.title}</div>

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
                alt={s} style={{ width: '100%', border: '1px solid var(--border)', borderRadius: 6 }} />
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

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
        <div className="field">
          <label>Assignee</label>
          <select value={assigneeId} onChange={(e) => setAssigneeId(Number(e.target.value) || 0)}>
            <option value={0}>Unassigned</option>
            {users.map((u) => <option key={u.id} value={u.id}>{u.display_name || u.username}</option>)}
          </select>
        </div>
        <div className="field">
          <label>Fix due by (SLA)</label>
          <input type="date" value={dueDate}
            onChange={(e) => setDueDate(e.target.value)} />
        </div>
      </div>

      <div className="field">
        <label>Internal note</label>
        <textarea rows={2} value={note} onChange={(e) => setNote(e.target.value)}
          placeholder="Reason for the status change, e.g. false positive — resolver returns 200 for arbitrary vhosts" />
      </div>
    </Modal>
  )
}