import React, { useEffect, useState } from 'react'
import { api } from '../api.js'
import { Modal, useToast } from '../components.jsx'
import { IcoPlay } from '../icons.jsx'

const ICONS = {
  'app-web': '🌐',
  'app-api': '🔌',
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

function crumb(label) {
  return label.replace(/_/g, ' ')
}

function LaunchModal({ engine, onClose, onScanStart }) {
  const [targets, setTargets] = useState([])
  const [targetId, setTargetId] = useState('')
  const [profile, setProfile] = useState(engine.default_profile)
  const [params, setParams] = useState({})
  const [busy, setBusy] = useState(false)
  const [mode, setMode] = useState(null)
  const [usedCreds, setUsedCreds] = useState(false)
  const shout = useToast()

  const reconOnly = engine.profiles && engine.profiles.length === 1 &&
    engine.profiles[0] === 'recon'
  const MODES = (reconOnly ? [
    { id: 'gentle', label: 'Recon pass', profile: 'recon',
      aggressive: false, desc: 'Fast, low-noise surface mapping' },
  ] : [
    { id: 'gentle', label: 'Stealthy / read-only', profile: 'quick',
      aggressive: false, desc: 'Non-intrusive recon + checks, no exploitation' },
    { id: 'auto', label: 'Active & auto-exploit', profile: engine.default_profile,
      aggressive: false, desc: 'Proof-gated automated exploitation of confirmed issues' },
    { id: 'deep', label: 'Deep coverage', profile: 'deep', aggressive: false,
      desc: 'Larger crawl + injection surface, proof-gated exploitation' },
    { id: 'intrusive', label: 'Intrusive (aggressive)', profile: 'full',
      aggressive: true, desc: 'CVE RCE runners, brute force, exploitation channels' },
  ].filter((m) => (engine.profiles || []).includes(m.profile) || m.id === 'auto'))

  const schema = engine.params_schema || {}

  const credFields = []
  const optFields = []
  for (const [key, def] of Object.entries(schema)) {
    if (def.type === 'object' && (def.fields || []).length) {
      credFields.push(...def.fields.map((f) => ({ name: f, label: crumb(f) })))
    } else if (def.secret) {
      credFields.push({ name: key, label: def.label })
    } else {
      optFields.push([key, def])
    }
  }

  useEffect(() => {
    if (!mode && (engine.profiles || []).includes(engine.default_profile)) {
      pickMode(reconOnly ? 'gentle' :
        engine.default_profile === 'full' ? 'auto' : 'gentle')
    }
  }, [])

  useEffect(() => {
    api('/v1/targets').then((t) => {
      setTargets(t)
      const kinds = engine.target_kinds || []
      let pick = t.find((x) => kinds.includes(x.kind)) || t[0] || null
      if (pick) setTargetId(pick.id)
    }).catch((e) => shout.push(e.message, 'err'))
  }, [])

  function setParam(k, v) {
    setParams((p) => ({ ...p, [k]: v }))
  }

  function pickMode(m) {
    const def = MODES.find((x) => x.id === m)
    if (!def) return
    setMode(m)
    setProfile(def.profile)
    setParams((p) => ({ ...p, aggressive: def.aggressive }))
  }

  async function launch(e) {
    e.preventDefault()
    if (!targetId) return shout.push('add a compatible target first', 'err')
    const body = { target_id: parseInt(targetId, 10), engine_id: engine.engine_id, profile, params }
    if (!usedCreds) {
      const clean = { ...params }
      credFields.forEach((f) => delete clean[f.name])
      body.params = clean
    }
    setBusy(true)
    try {
      const r = await shout.api(() => api('/v1/scans', { method: 'POST', body }))
      shout.push(`Scan #${r.id} queued`)
      onScanStart(r.id)
    } catch (e2) { setBusy(false) }
  }

  const kinds = engine.target_kinds || []
  const shown = targets.filter((t) => kinds.includes(t.kind))

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
          <label>Operation mode</label>
          {MODES.map((m) => (
            <label key={m.id} style={{ display: 'flex', gap: 8, alignItems: 'flex-start', cursor: 'pointer', padding: '4px 0' }}>
              <input type="radio" style={{ width: 'auto', marginTop: 3 }}
                checked={mode === m.id} onChange={() => pickMode(m.id)} />
              <span>
                <b>{m.label}</b>
                <span className="muted" style={{ display: 'block', fontSize: 11.5 }}>{m.desc}</span>
              </span>
            </label>
          ))}
        </div>
        <div className="field" style={{ display: 'flex', gap: 12, alignItems: 'center' }}>
          <label>Profile</label>
          <select value={profile} onChange={(e) => setProfile(e.target.value)}>
            {(engine.profiles || []).map((p) => <option key={p} value={p}>{p}</option>)}
          </select>
          <span className="muted" style={{ fontSize: 11.5 }}>in sync with the selected mode</span>
        </div>
        <div className="field">
          <label>Target</label>
          <select value={targetId} onChange={(e) => setTargetId(e.target.value)}>
            {shown.length === 0 && <option value="">No compatible targets ({kinds.join(', ')}) — add one on the Targets page</option>}
            {shown.map((t) => <option key={t.id} value={t.id}>{t.address} ({t.kind})</option>)}
          </select>
        </div>

        {credFields.length > 0 && (
          <div className="field">
            <label>Credentials</label>
            <div className="seg">
              <button type="button" className={!usedCreds ? 'seg-btn on' : 'seg-btn'}
                onClick={() => setUsedCreds(false)}>Without credentials</button>
              <button type="button" className={usedCreds ? 'seg-btn on' : 'seg-btn'}
                onClick={() => setUsedCreds(true)}>With credentials</button>
            </div>
            {usedCreds && (
              <div className="credbox">
                <div className="muted" style={{ fontSize: 11.5, marginBottom: 10 }}>
                  Optional — leave blank to keep the scan unauthenticated.
                </div>
                {credFields.map((f) => (
                  <div key={f.name} className="field" style={{ marginTop: 6 }}>
                    <input type="password" autoComplete="off" placeholder={f.label}
                      value={params[f.name] || ''}
                      onChange={(e) => setParam(f.name, e.target.value)} />
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {optFields.length > 0 && (
          <div className="field">
            <label>Advanced options</label>
            {optFields.map(([key, def]) => (
              <div className="field" key={key} style={{ marginTop: 4 }}>
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
                ) : (
                  <input type={def.secret ? 'password' : 'text'} autoComplete="off"
                    placeholder={def.label}
                    value={params[key] || ''}
                    onChange={(e) => setParam(key, e.target.value)} />
                )}
              </div>
            ))}
          </div>
        )}
      </form>
    </Modal>
  )
}