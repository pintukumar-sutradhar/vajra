import React, { useEffect, useRef, useState } from 'react'
import { api, apiBlob, streamEvents } from '../api.js'
import { Pill, ScanStatus, Spinner, useToast } from '../components.jsx'
import { IcoStop, IcoDoc, IcoRefreshCw, IcoChev } from '../icons.jsx'

const TERMINAL = { completed: 1, failed: 1, canceled: 1 }

function fmtElapsed(start) {
  const s = start ? Math.max(0, (Date.now() - new Date(start).getTime()) / 1000) : 0
  const t = Math.floor(s)
  const h = Math.floor(t / 3600)
  const m = Math.floor((t % 3600) / 60)
  const sec = t % 60
  const pad = (n) => String(n).padStart(2, '0')
  return h > 0 ? `${h}:${pad(m)}:${pad(sec)}` : `${pad(m)}:${pad(sec)}`
}

function useTicker(active) {
  const [, force] = useState(0)
  useEffect(() => {
    if (!active) return
    const t = setInterval(() => force((x) => x + 1), 1000)
    return () => clearInterval(t)
  }, [active])
}

function LiveState({ scan, running }) {
  useTicker(running)
  const pct = Math.round(scan.progress || 0)
  return (
    <div className="tracker">
      <div className="tracker-slot">
        <div className="progress lg"><i style={{ width: pct + '%' }} /></div>
        <span className="mono pct">{pct}%</span>
      </div>
      <div className="tracker-meta">
        <span className="chip"><ScanStatus value={scan.status} /></span>
        {running
          ? <span className="chip chip-alive">elapsed {fmtElapsed(scan.started_at)}</span>
          : <span className="chip">took {fmtElapsed(scan.started_at)}</span>}
        <span className="chip">engine {scan.engine_id}</span>
        <span className="chip">profile {scan.profile}</span>
        {scan.stats && (scan.stats.findings || 0) > 0 && (
          <span className="chip">{scan.stats.findings} findings</span>
        )}
      </div>
      {scan.error && <div className="errorbox" style={{ marginTop: 12 }}>{scan.error}</div>}
    </div>
  )
}

export default function ScanDetail({ id }) {
  const [scan, setScan] = useState(null)
  const [events, setEvents] = useState([])
  const [findings, setFindings] = useState(null)
  const [err, setErr] = useState('')
  const [tab, setTab] = useState('events')
  const shout = useToast()
  const evRef = useRef(null)

  async function load() {
    try {
      const s = await api('/v1/scans/' + id)
      setScan(s)
      const done = TERMINAL[s.status]
      setTab((t) => done && t === 'events' ? 'report' : t)
    } catch (e) {
      setErr(e.message)
    }
  }

  useEffect(() => { load() }, [id])

  /* Live event stream. The API replays from 'last' and sends 'event: done' on
     terminal state. */
  useEffect(() => {
    const ctrl = new AbortController()
    streamEvents(`/v1/scans/${id}/events?last=0`, {
      signal: ctrl.signal,
      onEvent: (ev) => {
        if (!ev || ev.type === 'eof') return
        setEvents((list) => (list.some((x) => x.id === ev.id) ? list : [...list, ev]).slice(-500))
      },
      onDone: () => load(),
    })
    return () => ctrl.abort()
  }, [id])

  /* Findings available live once harvested; reload after completion. */
  async function loadFindings() {
    try {
      const r = await api('/v1/scans/' + id + '/findings')
      setFindings(Array.isArray(r) ? r : [])
    } catch (e) { /* keep previous data */ }
  }
  useEffect(() => {
    setFindings(null)
    loadFindings()
  }, [id, scan && TERMINAL[scan.status] ? 'final' : 'live'])

  const running = scan && !TERMINAL[scan.status]

  /* Poll scan + findings while running so progress and live findings move. */
  useEffect(() => {
    if (!running) return
    const t = setInterval(() => { load(); loadFindings() }, 4000)
    return () => clearInterval(t)
  }, [id, running])

  async function download(path, fname) {
    try {
      const blob = await apiBlob(path)
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = fname
      document.body.appendChild(a)
      a.click()
      a.remove()
      URL.revokeObjectURL(url)
    } catch (e) {
      shout('Download failed: ' + (e.message || e.status), 'error')
    }
  }
  const downloadPdf = () => download('/v1/reports/' + id + '/pdf', 'vajra-pentest-report-' + id + '.pdf')
  const downloadHtml = () => download('/v1/reports/' + id + '/html?download=1', 'vajra-pentest-report-' + id + '.html')

  if (err) return <div className="errorbox">{err}</div>
  if (!scan) return <div className="muted"><Spinner /> Loading…</div>

  const done = TERMINAL[scan.status] ? 1 : 0
  const reportState = scan.status === 'completed' || scan.status === 'failed'

  return (
    <>
      <div className="toolbar">
        <button className="btn sm" onClick={() => { window.location.hash = '#/scans' }} title="All scans">
          <IcoChev /> Back
        </button>
        <div>
          <h1 style={{ fontSize: 18 }}>Scan #{scan.id} <span className="muted mono">· {scan.target}</span></h1>
        </div>
        <div className="spacer" />
        <button className="btn sm" onClick={load} title="Refresh"><IcoRefreshCw /> Refresh</button>
        <ScanStatus value={scan.status} />
        {running && (
          <button className="btn danger" onClick={async () => {
            await shout.api(() => api('/v1/scans/' + id + '/cancel', { method: 'POST' }))
            load()
          }}><IcoStop /> Cancel run</button>
        )}
      </div>

      <div className="card" style={{ marginBottom: 16 }}>
        <LiveState scan={scan} running={running} />
        {scan.stats && scan.stats.by_severity && Object.keys(scan.stats.by_severity).length > 0 && (
          <div style={{ display: 'flex', gap: 8, marginTop: 12, flexWrap: 'wrap' }}>
            {Object.entries(scan.stats.by_severity).map(([k, v]) => (
              <Pill key={k} className={'sev-' + k}>{k} {v}</Pill>
            ))}
          </div>
        )}
      </div>

      <div className="toolbar">
        <button className={'btn ' + (tab === 'events' ? 'primary' : '')} onClick={() => setTab('events')}>
          Live log {running && <Spinner />}
        </button>
        <button className={'btn ' + (tab === 'findings' ? 'primary' : '')} onClick={() => setTab('findings')}>
          Findings ({(scan.stats && scan.stats.findings) || (findings ? findings.length : 0)})
        </button>
        {reportState && (
          <button className={'btn ' + (tab === 'report' ? 'primary' : '')} onClick={() => setTab('report')}>
            <IcoDoc /> Report
          </button>
        )}
      </div>

      {tab === 'events' && <EventsLog events={events} running={running} />}

      {tab === 'findings' && (
        <FindingsView rows={findings} scanId={id} running={running} />
      )}

      {tab === 'report' && (
        <>
          <div className="toolbar" style={{ justifyContent: 'flex-end', padding: '8px 0', gap: 8 }}>
            <button className="btn secondary" onClick={downloadHtml}><IcoDoc /> Download HTML report</button>
            <button className="btn secondary" onClick={downloadPdf}><IcoDoc /> Download PDF</button>
          </div>
          <iframe className="report-frame" src={'/api/v1/reports/' + id + '/html?download=0'} title="report" />
        </>
      )}
    </>
  )
}

function EventsLog({ events, running }) {
  const box = useRef(null)
  useEffect(() => { box.current && (box.current.scrollTop = box.current.scrollHeight) }, [events.length, running])
  return (
    <div className="ev-log" ref={box}>
      {events.length === 0 && !running && <div className="row muted">No log output recorded.</div>}
      {events.map((e) => (
        <div className="row" key={e.id}>
          <span className="ts">{e.ts ? new Date(e.ts).toLocaleTimeString() : ''}</span>
          <span className={'lv-' + (e.level || 'info')}>{e.message}</span>
        </div>
      ))}
      {running && <div className="row"><Spinner /> listening for updates…</div>}
    </div>
  )
}

function FindingsView({ rows, scanId, running }) {
  const [openId, setOpenId] = useState(null)
  if (!rows) return <div className="muted"><Spinner /> loading findings…</div>
  if (!rows.length) {
    return running
      ? <div className="empty">No findings harvested yet — they appear here live as the engine reports them.</div>
      : <div className="empty">No findings recorded on this scan.</div>
  }
  const shots = (f) => (f.evidence && f.evidence.screenshots) || []
  return (
    <div>
      {rows.map((f) => (
        <details className="poc" key={f.id} open={openId === f.id}>
          <summary onClick={(e) => { e.preventDefault(); setOpenId(openId === f.id ? null : f.id) }}>
            <span style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
              <Pill className={'sev-' + f.severity}>{f.severity}</Pill>
              <span>{f.title}</span>
              <span className="muted mono" style={{ marginLeft: 'auto', fontSize: 11.5 }}>{f.ref}</span>
            </span>
          </summary>
          <div className="inner">
            <div style={{ display: 'grid', gridTemplateColumns: 'auto 1fr', gap: '8px 18px', fontSize: 13 }}>
              <span className="muted">Module</span><span className="mono">{f.source_module}</span>
              <span className="muted">Confidence</span><span><Pill className={'ci-' + f.confidence}>{f.confidence}</Pill></span>
              <span className="muted">Category</span><span>{f.category || '—'}</span>
              <span className="muted">Asset</span><span className="mono">{f.asset}</span>
            </div>
            {f.detail && (
              <>
                <div className="section-title">Detail</div>
                <div className="mono-block">{f.detail}</div>
              </>
            )}
            {f.evidence && f.evidence.text && (
              <>
                <div className="section-title">Proof of concept / observed evidence</div>
                <div className="mono-block">{f.evidence.text}</div>
              </>
            )}
            {shots(f).length > 0 && (
              <>
                <div className="section-title">PoC screenshots</div>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(230px, 1fr))', gap: 10 }}>
                  {shots(f).map((s) => (
                    <a key={s} href={'/api/v1/reports/' + scanId + '/static/' + s} target="_blank" rel="noreferrer">
                      <img src={'/api/v1/reports/' + scanId + '/static/' + s}
                        alt={s} style={{ width: '100%', border: '1px solid var(--border)', borderRadius: 6 }} />
                    </a>
                  ))}
                </div>
              </>
            )}
            {f.remediation && (
              <>
                <div className="section-title">Remediation</div>
                <div className="mono-block" style={{ color: 'var(--text)', maxHeight: 200 }}>{f.remediation}</div>
              </>
            )}
          </div>
        </details>
      ))}
    </div>
  )
}