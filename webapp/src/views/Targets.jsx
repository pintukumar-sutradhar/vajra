import React, { useEffect, useState } from 'react'
import { api } from '../api.js'
import { Modal, Empty, useToast } from '../components.jsx'
import { IcoPlus, IcoClose } from '../icons.jsx'

const KINDS = ['url', 'ip', 'cidr', 'hostname', 'domain']

export default function Targets() {
  const [targets, setTargets] = useState(null)
  const [open, setOpen] = useState(false)
  const shout = useToast()

  function load() {
    api('/v1/targets').then(setTargets).catch((e) => shout.push(e.message, 'err'))
  }
  useEffect(load, [])

  return (
    <>
      <div className="toolbar">
        <button className="btn primary" onClick={() => setOpen(true)}><IcoPlus /> New target</button>
      </div>

      {!targets
        ? <div className="muted">Loading…</div>
        : targets.length === 0
          ? <Empty icon="🎯" text="No targets yet. Add an asset, then start a scan from the Engines page." />
          : (
            <div className="card">
              <table className="vt">
                <thead>
                  <tr><th>Name</th><th>Address</th><th>Kind</th><th>Tags</th><th>Added</th></tr>
                </thead>
                <tbody>
                  {targets.map((t) => (
                    <tr key={t.id}>
                      <td><b>{t.name || t.address}</b></td>
                      <td className="mono">{t.address}</td>
                      <td><span className="tag">{t.kind}</span></td>
                      <td className="muted">{(t.tags && Object.keys(t.tags).join(', ')) || '—'}</td>
                      <td className="muted">{new Date(t.created_at).toLocaleDateString()}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

      {open && <NewTarget onClose={() => setOpen(false)} onDone={() => { setOpen(false); load() }} />}
    </>
  )
}

function NewTarget({ onClose, onDone }) {
  const shout = useToast()
  const [form, setForm] = useState({ kind: 'url', address: '', name: '', tags: '', authorization_proof: '' })
  const [busy, setBusy] = useState(false)

  const set = (k) => (e) => setForm((f) => ({ ...f, [k]: e.target.value }))

  async function submit(e) {
    e.preventDefault()
    if (!form.address.trim()) return shout.push('address is required', 'err')
    setBusy(true)
    try {
      const tags = {}
      if (form.tags) {
        for (const kv of form.tags.split(',')
          .map((s) => s.trim())
          .filter(Boolean)) {
          const [k, ...rest] = kv.split('=')
          tags[k] = rest.join('=') || ''
        }
      }
      const body = {
        kind: form.kind, address: form.address.trim(),
        name: form.name, tags,
        authorization_proof: form.authorization_proof.trim(),
      }
      const r = await shout.api(() => api('/v1/targets', { method: 'POST', body }))
      shout.push(`Target #${r.id} created`)
      onDone()
    } catch (e) { /* toast handled */ setBusy(false) }
  }

  return (
    <Modal title="New target" onClose={onClose}
      foot={<>
        <button className="btn" onClick={onClose}>Cancel</button>
        <button className="btn primary" onClick={submit} disabled={busy}>{busy ? 'Adding…' : 'Add target'}</button>
      </>}>
      <form onSubmit={submit}>
        <div className="field">
          <label>Kind</label>
          <select value={form.kind} onChange={set('kind')}>
            {KINDS.map((k) => <option key={k} value={k}>{k}</option>)}
          </select>
        </div>
        <div className="field">
          <label>Address / target</label>
          <input value={form.address} onChange={set('address')}
            placeholder={form.kind === 'url' ? 'https://app.example.com' : form.kind === 'cidr' ? '10.0.0.0/16' : 'example.com'} />
        </div>
        <div className="field">
          <label>Name (optional)</label>
          <input value={form.name} onChange={set('name')} placeholder="Friendly label" />
        </div>
        <div className="field">
          <label>Tags (optional, comma-separated key=value)</label>
          <input value={form.tags} onChange={set('tags')} placeholder="env=prod,owner=payments" />
        </div>
        <div className="field">
          <label>Authorization proof (required)</label>
          <textarea rows={3} value={form.authorization_proof} onChange={set('authorization_proof')}
            placeholder="Explicit authorized-scope reference, e.g. engagement ID / ticket / signed scope statement." />
          <div className="hint">VAJRA refuses to scan a target without an explicit authorized-scope reference. This is recorded in the audit log with every scan.</div>
        </div>
      </form>
    </Modal>
  )
}