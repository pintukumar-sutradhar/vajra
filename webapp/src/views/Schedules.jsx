import React, { useEffect, useState } from 'react'
import { api } from '../api.js'
import { Modal, Empty, useToast } from '../components.jsx'
import { IcoPlus, IcoClock } from '../icons.jsx'

export default function Schedules() {
  const [rows, setRows] = useState(null)
  const [engines, setEngines] = useState([])
  const [open, setOpen] = useState(false)
  const [toEdit, setToEdit] = useState(null)
  const [toDelete, setToDelete] = useState(null)
  const [busyId, setBusyId] = useState(0)
  const shout = useToast()

  function load() {
    api('/v1/schedules').then(setRows).catch((e) => shout.push(e.message, 'err'))
  }
  useEffect(load, [])
  useEffect(() => {
    api('/v1/engines').then(setEngines).catch(() => {})
  }, [])

  async function runIt(s) {
    setBusyId(s.id)
    try {
      const r = await shout.api(() => api('/v1/schedules/' + s.id + '/run', { method: 'POST', body: {} }))
      shout.push('Schedule fired — scan #' + r.scan_id + ' queued', 'ok')
      load()
    } catch (e) { /* toast */ }
    setBusyId(0)
  }

  async function toggle(s) {
    try {
      await shout.api(() => api('/v1/schedules/' + s.id, { method: 'PATCH', body: { enabled: !s.enabled } }))
      load()
    } catch (e) { /* toast */ }
  }

  const engineLabel = (id) => {
    const e = engines.find((x) => x.engine_id === id)
    return e ? e.label : id
  }

  return (
    <>
      <div className="toolbar">
        <button className="btn primary" onClick={() => setOpen(true)}><IcoPlus /> New schedule</button>
        <span className="chip muted">Recurring scans are enqueued automatically by the worker</span>
      </div>

      {!rows
        ? <div className="muted">Loading…</div>
        : rows.length === 0
          ? <Empty icon={<IcoClock />} text="No schedules yet. Plan recurring scans against a target, then let the worker fire them." />
          : (
            <div className="card">
              <table className="vt">
                <thead>
                  <tr><th>Label</th><th>Target</th><th>Engine</th><th>Profile</th><th>Interval</th><th>Next run</th><th>Last run</th><th>State</th><th></th></tr>
                </thead>
                <tbody>
                  {rows.map((s) => (
                    <tr key={s.id}>
                      <td><b>{s.label || 'Schedule #' + s.id}</b></td>
                      <td className="mono">{s.target}</td>
                      <td>{engineLabel(s.engine_id)}</td>
                      <td><span className="tag">{s.profile}</span></td>
                      <td className="mono">{s.interval_hours >= 24
                        ? (s.interval_hours / 24).toFixed(0) + 'd'
                        : s.interval_hours + 'h'}</td>
                      <td className="muted">{s.next_run ? new Date(s.next_run + 'Z').toLocaleString() : '—'}</td>
                      <td className="muted">
                        {s.last_run_at
                          ? <span>{new Date(s.last_run_at + 'Z').toLocaleDateString()}
                            {s.last_scan_id ? ' · #' + s.last_scan_id : ''}</span>
                          : 'never'}
                      </td>
                      <td>
                        <label className="switch" title={s.enabled ? 'Enabled — click to pause' : 'Paused — click to enable'}>
                          <input type="checkbox" checked={s.enabled} onChange={() => toggle(s)} />
                          <span className="slider" />
                        </label>
                      </td>
                      <td style={{ textAlign: 'right', whiteSpace: 'nowrap' }}>
                        <button className="btn sm" disabled={busyId === s.id} onClick={() => runIt(s)}>
                          {busyId === s.id ? '…' : 'Run now'}
                        </button>
                        <button className="btn sm" onClick={() => setToEdit(s)}>Edit</button>
                        <button className="btn danger sm" onClick={() => setToDelete(s)}>Delete</button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

      {(open || toEdit) && <ScheduleModal edit={toEdit}
        onClose={() => { setOpen(false); setToEdit(null) }}
        onDone={() => { setOpen(false); setToEdit(null); load() }} />}
      {toDelete && <DeleteSchedule row={toDelete}
        onClose={() => setToDelete(null)} onDone={() => { setToDelete(null); load() }} />}
    </>
  )
}

function DeleteSchedule({ row, onClose, onDone }) {
  const shout = useToast()
  const [busy, setBusy] = useState(false)
  async function del(e) {
    e.preventDefault()
    setBusy(true)
    try {
      await shout.api(() => api('/v1/schedules/' + row.id, { method: 'DELETE' }))
      shout.push('Schedule removed')
      onDone()
    } catch (err) { setBusy(false) }
  }
  return (
    <Modal title="Delete schedule" onClose={onClose}
      foot={<>
        <button className="btn" onClick={onClose}>Cancel</button>
        <button className="btn danger" onClick={del} disabled={busy}>{busy ? 'Deleting…' : 'Delete schedule'}</button>
      </>}>
      <p>Delete <b>{row.label || 'Schedule #' + row.id}</b> ({row.target})? It will stop firing, but already-run scans are kept.</p>
    </Modal>
  )
}

function ScheduleModal({ edit, onClose, onDone }) {
  const [targets, setTargets] = useState([])
  const [engines, setEngines] = useState([])
  const [form, setForm] = useState({
    target_id: edit ? edit.target_id : '',
    engine_id: edit ? edit.engine_id : '',
    profile: edit ? edit.profile : 'full',
    interval_hours: edit ? edit.interval_hours : 24,
    label: edit ? edit.label : '',
    enabled: edit ? edit.enabled : true,
    params: edit ? (edit.params || {}) : {},
  })
  const [busy, setBusy] = useState(false)
  const shout = useToast()

  useEffect(() => {
    api('/v1/targets').then((t) => {
      setTargets(t)
      if (!edit && t.length) setForm((f) => ({ ...f, target_id: t[0].id }))
    }).catch(() => {})
    api('/v1/engines').then((e) => {
      setEngines(e)
      if (!edit) return
      setForm((f) => ({ ...f, engine_id: e.find((x) => x.engine_id === f.engine_id)
        ? f.engine_id : (e[0] && e[0].engine_id) || '' }))
    }).catch(() => {})
  }, [edit])

  const selEngine = engines.find((e) => e.engine_id === form.engine_id)
  const PROFILES = (selEngine && selEngine.profiles || []).filter((p) =>
    ['quick', 'full', 'deep', 'recon'].includes(p))

  function set(k, v) {
    setForm((f) => ({ ...f, [k]: v }))
  }

  async function submit(e) {
    e.preventDefault()
    if (!form.target_id || !form.engine_id) return shout.push('pick a target and engine', 'err')
    setBusy(true)
    const body = {
      target_id: parseInt(form.target_id, 10),
      engine_id: form.engine_id,
      profile: form.profile,
      params: form.params || {},
      label: form.label,
      interval_hours: parseFloat(form.interval_hours) || 24,
      enabled: form.enabled,
    }
    try {
      await shout.api(() => api(edit ? '/v1/schedules/' + edit.id : '/v1/schedules', {
        method: edit ? 'PATCH' : 'POST', body,
      }))
      shout.push(edit ? 'Schedule updated' : 'Schedule created')
      onDone()
    } catch (e) { setBusy(false) }
  }

  const compatible = selEngine ? targets.filter((t) =>
    (selEngine.target_kinds || []).includes(t.kind)) : targets

  return (
    <Modal title={engine ? 'Edit schedule' : 'New schedule'} onClose={onClose} wide
      foot={<>
        <button className="btn" onClick={onClose}>Cancel</button>
        <button className="btn primary" onClick={submit} disabled={busy}>
          {busy ? 'Saving…' : edit ? 'Save' : 'Create schedule'}
        </button>
      </>}>
      <form onSubmit={submit}>
        <div className="field">
          <label>Label (optional)</label>
          <input value={form.label} onChange={(e) => set('label', e.target.value)}
            placeholder="e.g. Weekly full scan of customer portal" />
        </div>
        <div className="field">
          <label>Engine</label>
          <select value={form.engine_id} onChange={(e) => { set('engine_id', e.target.value); set('profile', '') }}>
            <option value="">Select engine…</option>
            {engines.map((e) => <option key={e.engine_id} value={e.engine_id}>{e.label}</option>)}
          </select>
          {selEngine && <div className="hint">{selEngine.description}</div>}
        </div>
        <div className="field">
          <label>Target</label>
          <select value={form.target_id} onChange={(e) => set('target_id', e.target.value)}>
            {compatible.length === 0 && <option value="">No compatible targets — add one on the Targets page</option>}
            {compatible.map((t) => <option key={t.id} value={t.id}>{t.address} ({t.kind})</option>)}
          </select>
        </div>
        {PROFILES.length > 0 && (
          <div className="field">
            <label>Profile</label>
            <div className="seg">
              {PROFILES.map((p) => (
                <button type="button" key={p}
                  className={'seg-btn' + (form.profile === p ? ' on' : '')}
                  onClick={() => set('profile', p)}>{p}</button>
              ))}
            </div>
          </div>
        )}
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
          <div className="field">
            <label>Interval</label>
            <input type="number" min="0.25" step="0.25" value={form.interval_hours}
              onChange={(e) => set('interval_hours', e.target.value)} />
            <div className="hint">Hours between runs (24 = daily, 168 = weekly). Minimum 0.25.</div>
          </div>
          <div className="field">
            <label>State</label>
            <label className="switch" style={{ marginTop: 6 }}>
              <input type="checkbox" checked={form.enabled}
                onChange={(e) => set('enabled', e.target.checked)} />
              <span className="slider" />
              <span className="switch-label">{form.enabled ? 'Enabled' : 'Paused'}</span>
            </label>
          </div>
        </div>
      </form>
    </Modal>
  )
}