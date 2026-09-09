import React, { useEffect, useRef, useState } from 'react'
import { api, apiBlob, streamEvents } from '../api.js'
import { Pill, ScanStatus, Elapsed, Spinner, useToast } from '../components.jsx'
import { IcoStop, IcoDoc, IcoChev } from '../icons.jsx'

const TERMINAL = { completed: 1, failed: 1, canceled: 1 }

export default function ScanDetail({ id }) {
  const [scan, setScan] = useState(null)
  const [events, setEvents] = useState([])
  const [findings, setFindings] = useState(null)
  const [err, setErr] = useState('')
  const [tab, setTab] = useState('events')
  const [reportUrl, setReportUrl] = useState('')
  const shout = useToast()
  const evRef = useRef(null)

  async function load() {
    try {
      const s = await api('/v1/scans/' + id)
      setScan(s)
      setTab((t) => s.status === 'completed' && t === 'events' ? 'report' : t)
    } catch (e) {
      setErr(e.message)
    }
  }

  useEffect(() => { load() }, [id])

  /* Live event stream. On completion the API sends 'event: done' and we
     refresh the scan/findings. Reconnect only when the scan id changes. */
  useEffect(() => {
    const ctrl = new AbortController()
    let lastId = 0
    streamEvents(`/v1/scans/${id}/events?last=0`, {
      signal: ctrl.signal,
      onEvent: (ev) => {
        if (!ev || ev.type === 'eof') return
        lastId = Math.max(lastId, ev.id || 0)
        setEvents((list) => (list.some((x) => x.id === ev.id) ? list : [...list, ev]).slice(-400))
      },
      onDone: () => load(),
    })
    return () => ctrl.abort()
  }, [id])

  useEffect(() => {
    setFindings(null)
    api('/v1/scans/' + id + '/findings').then(setFindings).catch(() => setFindings([]))
  }, [id, scan && scan.status])

  const running = scan && !TERMINAL[scan.status]

  // Poll while running so the progress bar moves; the SSE stream only carries events.
  useEffect(() => {
    if (!running) return
    const t = setInterval(load, 5000)
    return () => clearInterval(t)
  }, [id, scan && scan.status])

  async function downloadPdf() {
    try {
      const blob = await apiBlob('/v1/reports/' + id + '/pdf')
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = 'vajra-pentest-report-' + id + '.pdf'
      document.body.appendChild(a)
      a.click()
      a.remove()
      URL.revokeObjectURL(url)
    } catch (e) {
      shout('PDF download failed: ' + (e.message || e.status), 'error')
    }
  }

  async function downloadHtml() {
    try {
      const blob = await apiBlob('/v1/reports/' + id + '/static/report.html')
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = 'vajra-pentest-report-' + id + '.html'
      document.body.appendChild(a)
      a.click()
      a.remove()
      URL.revokeObjectURL(url)
    } catch (e) {
      shout('HTML download failed: ' + (e.message || e.status), 'error')
    }
  }

  if (err) return <div className="errorbox">{err}</div>
  if (!scan) return <div className="muted"><Spinner /> Loading…</div>

  return (
    <>
      <div className="toolbar">
        <div>
          <h1 style={{ fontSize: 18 }}>Scan #{scan.id} · <span className="mono">{scan.target}</span></h1>
          <div className="muted" style={{ fontSize: 12.5, marginTop: 3 }}>
            {scan.engine_id} engine · {scan.profile} profile · started <Elapsed at={scan.started_at} done={!running} />
          </div>
        </div>
        <div className="spacer" />
        <ScanStatus value={scan.status} />
        {running && (
          <button className="btn danger" onClick={async () => {
            await shout.api(() => api('/v1/scans/' + id + '/cancel', { method: 'POST' }))
            load()
          }}><IcoStop /> Cancel</button>
        )}
      </div>

      <div className="card" style={{ marginBottom: 16 }}>
        <div style={{ display: 'flex', gap: 14, alignItems: 'center' }}>
          <div className="progress" style={{ flex: 1 }}><i style={{ width: (scan.progress || 0) + '%' }} /></div>
          <span className="mono muted">{Math.round(scan.progress || 0)}%</span>
        </div>
        {scan.error && <div className="errorbox" style={{ marginBottom: 0, marginTop: 12 }}>{scan.error}</div>}
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
        {scan.status === 'completed' && (
          <>
            <button className={'btn ' + (tab === 'report' ? 'primary' : '')}
              onClick={() => { setTab('report'); setReportUrl('/v1/reports/' + id + '/static/report.html') }}>
              <IcoDoc /> Report
            </button>
            <button className={'btn ' + (tab === 'findings' ? 'primary' : '')} onClick={() => setTab('findings')}>
              Findings ({(scan.stats && scan.stats.findings) || 0})
            </button>
          </>
        )}
      </div>

      {tab === 'events' && <EventsLog events={events} running={running} />}
      {tab === 'report' && (
        <>
          <div className="toolbar" style={{ justifyContent: 'flex-end', padding: '8px 0', gap: 8 }}>
            <button className="btn secondary" onClick={downloadHtml}>
              <IcoDoc /> Download HTML
            </button>
            <button className="btn secondary" onClick={downloadPdf}>
              <IcoDoc /> Download PDF
            </button>
          </div>
          <iframe className="report-frame" src={reportUrl} title="report" />
        </>
      )}
      {tab === 'findings' && <FindingsView rows={findings} scanId={id} />}
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

function FindingsView({ rows, scanId }) {
  const [openId, setOpenId] = useState(null)
  if (!rows) return <div className="muted"><Spinner /> loading findings…</div>
  if (!rows.length) return <div className="empty">No findings recorded on this scan.</div>
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
                        alt={s} style={{ width: '100%', border: '1px solid var(--line)', borderRadius: 6 }} />
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