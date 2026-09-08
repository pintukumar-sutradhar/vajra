import React, { useEffect, useState } from 'react'
import { api } from '../api.js'
import { Modal, useToast } from '../components.jsx'
import { IcoPlay } from '../icons.jsx'

const ICONS = {
  'app-web': '🌐',
  'app-infra': '🖥️',
  'app-ad': '🏛️',
  'app-external': '🗺️',
  default: '⚙️',
}

export default function Engines({ onScanStart }) {
  const [engines, setEngines] = useState(null)
  const [sel, setSel] = useState(null)
  const shout = useToast()

  useEffect(() => {
    api('/v1/engines').then(setEngines).catch((e) => shout.push(e.message, 'err'))
  }, [])

  if (!engines) return <div className="muted">Loading…</div>

  return (
    <>
      <div className="grid c3">
        {engines.map((e) => (
          <div className="engcard" key={e.engine_id}>
            <div className="etitle">
              <span style={{ fontSize: 22 }}>{ICONS[e.icon] || ICONS.default}</span>
              <span className="elabel">{e.label}</span>
            </div>
            <div className="edesc">{e.description}</div>
            <div className="ekinds">
              {(e.target_kinds || []).map((k) => <span className="tag" key={k}>{k}</span>)}
            </div>
            <div className="ekinds">
              {(e.profiles || []).map((p) => <span className="tag" key={p}>{p}</span>)}
            </div>
            <div className="spacer" style={{ height: 4 }} />
            <button className="btn primary" style={{ alignSelf: 'flex-start' }}
              onClick={() => setSel(e)}><IcoPlay /> Launch scan</button>
          </div>
        ))}
      </div>
      {sel && <LaunchModal engine={sel} onClose={() => setSel(null)}
        onScanStart={(id) => { setSel(null); onScanStart && onScanStart(id) }} />}
    </>
  )
}

function LaunchModal({ engine, onClose, onScanStart }) {
  const [targets, setTargets] = useState([])
  const [targetId, setTargetId] = useState('')
  const [profile, setProfile] = useState(engine.default_profile)
  const [params, setParams] = useState({})
  const [busy, setBusy] = useState(false)
  const shout = useToast()

  useEffect(() => {
    api('/v1/targets').then((t) => {
      setTargets(t)
      if (t.length && !t.some((x) => x.id === targetId)) setTargetId(t[0].id)
    }).catch((e) => shout.push(e.message, 'err'))
  }, [])

  function setParam(k, v) {
    setParams((p) => ({ ...p, [k]: v }))
  }

  async function launch(e) {
    e.preventDefault()
    if (!targetId) return shout.push('add a target first', 'err')
    setBusy(true)
    try {
      const r = await shout.api(() => api('/v1/scans', {
        method: 'POST',
        body: {
          target_id: parseInt(targetId, 10),
          engine_id: engine.engine_id,
          profile,
          params,
        },
      }))
      shout.push(`Scan #${r.id} queued`)
      onScanStart(r.id)
    } catch (e2) { setBusy(false) }
  }

  const schema = engine.params_schema || {}

  return (
    <Modal title={`Launch ${engine.label} scan`} onClose={onClose} wide
      foot={<>
        <button className="btn" onClick={onClose}>Cancel</button>
        <button className="btn primary" onClick={launch} disabled={busy || !targetId}>
          {busy ? 'Queuing…' : 'Start scan'}
        </button>
      </>}>
      <form onSubmit={launch}>
        <div className="field">
          <label>Target</label>
          <select value={targetId} onChange={(e) => setTargetId(e.target.value)}>
            {targets.length === 0 && <option value="">No targets — add one on the Targets page</option>}
            {targets.map((t) => <option key={t.id} value={t.id}>{t.address} {t.kind ? `(${t.kind})` : ''}</option>)}
          </select>
        </div>
        <div className="field">
          <label>Profile</label>
          <select value={profile} onChange={(e) => setProfile(e.target.value)}>
            {(engine.profiles || []).map((p) => <option key={p} value={p}>{p}</option>)}
          </select>
        </div>

        {Object.entries(schema).map(([key, def]) => (
          <div className="field" key={key}>
            <label>{def.label}</label>
            {def.type === 'bool' ? (
              <div style={{ display: 'flex', gap: 14 }}>
                {['yes', 'no'].map((v) => (
                  <label key={v} style={{ display: 'flex', gap: 5, alignItems: 'center', cursor: 'pointer' }}>
                    <input type="radio" style={{ width: 'auto' }}
                      checked={Boolean(params[key]) === (v === 'yes')}
                      onChange={() => setParam(key, v === 'yes')} />
                    {v}
                  </label>
                ))}
              </div>
            ) : def.type === 'object' ? (
              <div className="card" style={{ padding: 12 }}>
                <div className="muted" style={{ fontSize: 11.5, marginBottom: 8 }}>
                  Authenticated scanning (leave blank for unauthenticated)
                </div>
                {(def.fields || []).map((f) => (
                  <div key={f} style={{ marginBottom: 7 }}>
                    <input placeholder={f.replace('_', ' ')}
                      value={params[f] || ''}
                      onChange={(e) => setParam(f, e.target.value)} />
                  </div>
                ))}
              </div>
            ) : (
              <input placeholder={def.label}
                value={params[key] || ''}
                onChange={(e) => setParam(key, e.target.value)} />
            )}
          </div>
        ))}
      </form>
    </Modal>
  )
}