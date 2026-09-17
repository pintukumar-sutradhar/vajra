import React, { useEffect, useMemo, useRef, useState } from 'react'
import { api, apiBlob, streamEvents } from '../api.js'
import {
  Pill, ScanStatus, Spinner, useToast, ProgressBar, StatTile, Tabs,
  ConfirmDialog, SearchBox, Toggle,
} from '../components.jsx'
import {
  IcoStop, IcoDoc, IcoRefreshCw, IcoChev, IcoPlay, IcoPause, IcoDownload,
  IcoShield, IcoFilter,
} from '../icons.jsx'

const TERMINAL = { completed: 1, failed: 1, canceled: 1 }

/* Log levels, most severe first — the filter chips read in that order because
   the reason to open this panel mid-scan is almost always "what went wrong". */
const KIND_ORDER = ['error', 'warning', 'finding', 'suppressed', 'phase',
  'info', 'debug', 'trace']
const KIND_LABEL = {
  error: 'error', warning: 'warn', finding: 'finding', suppressed: 'suppressed',
  phase: 'phase', info: 'info', debug: 'debug', trace: 'trace',
}
const SHOWN_BY_DEFAULT = ['error', 'warning', 'finding', 'suppressed', 'phase',
  'info']

/* What kind of line is this?
   The worker passes the engine's own level through, but the two lines an
   operator most needs to find — "[PROOF:...]" and "[SUPPRESS] ..." — are both
   emitted at DEBUG, so they are recognised by their marker rather than their
   level. Suppression is checked before the level fallback for exactly that
   reason. */
function kindOf(e) {
  const lv = (e.level || 'info').toLowerCase()
  if (lv === 'error' || lv === 'critical' || lv === 'fatal') return 'error'
  if (lv === 'warning' || lv === 'warn') return 'warning'
  const msg = e.message || ''
  if (/\[SUPPRESS\]/.test(msg)) return 'suppressed'
  if (/\[PROOF/.test(msg) || /\[FINDING\]/.test(msg)) return 'finding'
  if (KIND_LABEL[lv]) return lv
  return 'info'
}

function fmtDur(seconds) {
  const t = Math.max(0, Math.floor(seconds || 0))
  const h = Math.floor(t / 3600)
  const m = Math.floor((t % 3600) / 60)
  const s = t % 60
  const pad = (n) => String(n).padStart(2, '0')
  return h > 0 ? `${h}:${pad(m)}:${pad(s)}` : `${pad(m)}:${pad(s)}`
}

/* Wall-clock is wrong for a scan that was paused: the engine was not running,
   so counting those seconds makes the run look slower than it was and makes
   any ETA derived from it nonsense. Subtract what the platform knows it was
   stopped, including a pause that is still in progress. */
function workSeconds(scan) {
  if (!scan || !scan.started_at) return 0
  const start = new Date(scan.started_at).getTime()
  const end = scan.finished_at ? new Date(scan.finished_at).getTime() : Date.now()
  let s = (end - start) / 1000
  s -= scan.paused_seconds || 0
  if (scan.paused && scan.paused_at) {
    s -= (Date.now() - new Date(scan.paused_at).getTime()) / 1000
  }
  return Math.max(0, s)
}

function useTicker(active) {
  const [, force] = useState(0)
  useEffect(() => {
    if (!active) return
    const t = setInterval(() => force((x) => x + 1), 1000)
    return () => clearInterval(t)
  }, [active])
}

export default function ScanDetail({ id }) {
  const [scan, setScan] = useState(null)
  const [events, setEvents] = useState([])
  const [findings, setFindings] = useState(null)
  const [suppressed, setSuppressed] = useState(null)
  const [err, setErr] = useState('')
  const [tab, setTab] = useState('log')
  const [confirm, setConfirm] = useState(null)
  const [busy, setBusy] = useState(false)
  const shout = useToast()

  async function load() {
    try {
      const s = await api('/v1/scans/' + id)
      setScan(s)
      // A finished scan has nothing to watch, so land on the report — unless
      // the operator already went somewhere deliberate.
      if (TERMINAL[s.status]) setTab((t) => (t === 'log' ? 'report' : t))
    } catch (e) {
      setErr(e.message)
    }
  }

  useEffect(() => { setErr(''); load() }, [id])

  async function loadFindings() {
    try {
      const r = await api('/v1/scans/' + id + '/findings')
      setFindings(Array.isArray(r) ? r : [])
    } catch (e) { /* keep previous data */ }
  }

  async function loadSuppressed() {
    try {
      const r = await api('/v1/scans/' + id + '/suppressed')
      setSuppressed(Array.isArray(r) ? r : [])
    } catch (e) { /* keep previous data */ }
  }

  useEffect(() => { setEvents([]) }, [id])
  useEffect(() => { setFindings(null); setSuppressed(null); loadFindings(); loadSuppressed() }, [id])

  /* Live event stream: replays from 0 so a page opened mid-scan still shows
     everything the run has said so far. */
  useEffect(() => {
    const ctrl = new AbortController()
    streamEvents(`/v1/scans/${id}/events?last=0`, {
      signal: ctrl.signal,
      onEvent: (ev) => {
        if (!ev || ev.type === 'eof') return
        setEvents((list) => (list.some((x) => x.id === ev.id) ? list : [...list, ev]).slice(-2000))
      },
      onDone: () => { load(); loadFindings(); loadSuppressed() },
    })
    return () => ctrl.abort()
  }, [id])

  const running = scan && !TERMINAL[scan.status]
  const paused = !!(scan && scan.paused)

  // Tick once a second while live so the elapsed clock advances smoothly
  // rather than stepping with the 5s data poll.
  useTicker(!!running)

  /* Poll while live so progress, findings and the suppression ledger all move
     without the operator reloading. Findings and suppressions are harvested by
     the worker independently of the event stream. */
  useEffect(() => {
    if (!running) return
    const t = setInterval(() => { load(); loadFindings(); loadSuppressed() }, 5000)
    return () => clearInterval(t)
  }, [id, running])

  async function act(path, msg) {
    setBusy(true)
    try {
      await api('/v1/scans/' + id + path, { method: 'POST' })
      if (msg) shout.push(msg, 'ok')
      await load()
    } catch (e) {
      shout.push(e.message, 'err')
    } finally {
      setBusy(false)
      setConfirm(null)
    }
  }

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
  const downloadLog = () => download('/v1/scans/' + id + '/log', 'vajra-scan-' + id + '.log')

  if (err) return <div className="errorbox">{err}</div>
  if (!scan) return <div className="muted"><Spinner /> Loading…</div>

  const reportState = scan.status === 'completed' || scan.status === 'failed' ||
    scan.status === 'canceled'
  const nFindings = (scan.stats && scan.stats.findings) || (findings ? findings.length : 0)
  const nSuppressed = scan.suppressed_count || (suppressed ? suppressed.length : 0)

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
        {running && (paused
          ? <button className="btn primary" disabled={busy}
              onClick={() => act('/resume', 'Scan resumed')}><IcoPlay /> Resume</button>
          : <button className="btn" disabled={busy}
              onClick={() => act('/pause', 'Scan paused — the engine keeps its state')}>
              <IcoPause /> Pause</button>)}
        {running && (
          <button className="btn danger" onClick={() => setConfirm('cancel')}><IcoStop /> Cancel run</button>
        )}
      </div>

      <div className="card" style={{ marginBottom: 16 }}>
        <div className="tracker">
          <div className="tracker-slot">
            <ProgressBar value={scan.progress} large tone={paused ? 'paused' : undefined} />
            <span className="mono pct">{Math.round(scan.progress || 0)}%</span>
          </div>
          <div className="tracker-meta">
            <span className="chip"><ScanStatus value={scan.status} /></span>
            <span className={'chip' + (running && !paused ? ' chip-alive' : '')}>
              {running ? 'elapsed ' : 'took '}{fmtDur(workSeconds(scan))}
            </span>
            {(scan.paused_seconds || 0) > 0 && (
              <span className="chip">paused {fmtDur(scan.paused_seconds)}</span>
            )}
            <span className="chip">engine {scan.engine_id}</span>
            <span className="chip">profile {scan.profile}</span>
            {scan.verbose > 0 && (
              <Pill className={'verbose-' + scan.verbose}>
                {scan.verbose === 1 ? '-v decisions' : '-vv every probe'}
              </Pill>
            )}
          </div>
        </div>

        {paused && (
          <div className="ws-paused">
            <IcoPause />
            <span>
              Paused since {new Date(scan.paused_at).toLocaleTimeString()} — the
              engine process is stopped in place and holds everything it has
              found. Resume continues from here.
            </span>
          </div>
        )}
        {scan.error && <div className="errorbox" style={{ marginTop: 12 }}>{scan.error}</div>}

        <div className="ws-strip" style={{ marginTop: 14, marginBottom: 0 }}>
          <StatTile label="Findings proven" value={nFindings} tone={nFindings ? 'danger' : 'muted'} />
          <StatTile label="Candidates refused" value={nSuppressed} tone="muted" />
          <StatTile label="Severity mix"
            value={(scan.stats && scan.stats.by_severity
              ? Object.entries(scan.stats.by_severity)
                .sort((a, b) => b[1] - a[1]).slice(0, 3)
                .map(([k, v]) => `${v} ${k}`).join(' · ')
              : '—')} />
        </div>
      </div>

      <Tabs value={tab} onChange={setTab} tabs={[
        { id: 'log', label: 'Live log', count: events.length, tone: 'muted' },
        { id: 'findings', label: 'Findings', count: nFindings, tone: nFindings ? 'danger' : 'muted' },
        { id: 'suppressed', label: 'Refused', count: nSuppressed, tone: 'muted' },
        { id: 'report', label: 'Report', icon: <IcoDoc />, disabled: !reportState },
      ]} />

      {tab === 'log' && (
        <LogView events={events} running={running} verbose={scan.verbose || 0}
          onDownload={downloadLog} />
      )}

      {tab === 'findings' && (
        <FindingsView rows={findings} scanId={id} running={running} />
      )}

      {tab === 'suppressed' && <SuppressedView rows={suppressed} running={running} />}

      {tab === 'report' && (
        <>
          <div className="toolbar" style={{ justifyContent: 'flex-end', padding: '8px 0', gap: 8 }}>
            <button className="btn secondary" onClick={downloadHtml}><IcoDoc /> Download HTML report</button>
            <button className="btn secondary" onClick={downloadPdf}><IcoDoc /> Download PDF</button>
          </div>
          <iframe className="report-frame" src={'/api/v1/reports/' + id + '/html?download=0'} title="report" />
        </>
      )}

      {confirm === 'cancel' && (
        <ConfirmDialog
          title="Cancel this run?"
          busy={busy}
          tone="danger"
          confirmLabel="Cancel the scan"
          onClose={() => setConfirm(null)}
          onConfirm={() => act('/cancel')}
          body={<p>The engine is asked to stop and flush. It gets up to 20 seconds
            to finish writing evidence and reports before it is killed.</p>}
          note={<>Findings already proven are kept, imported and included in the
            report. Stopping does not discard them.</>}
        />
      )}
    </>
  )
}

/* ------------------------------------------------------------------ log -- */

function LogView({ events, running, verbose, onDownload }) {
  const [kinds, setKinds] = useState(() => {
    // Someone who launched with -v asked for the reasoning, so show it without
    // making them hunt for the filter that reveals it.
    const base = [...SHOWN_BY_DEFAULT]
    if (verbose >= 1) base.push('debug')
    if (verbose >= 2) base.push('trace')
    return base
  })
  const [q, setQ] = useState('')
  const [follow, setFollow] = useState(true)
  const box = useRef(null)

  const tagged = useMemo(
    () => events.map((e) => ({ ...e, kind: kindOf(e) })),
    [events])

  const counts = useMemo(() => {
    const c = {}
    for (const e of tagged) c[e.kind] = (c[e.kind] || 0) + 1
    return c
  }, [tagged])

  const shown = useMemo(() => {
    const needle = q.trim().toLowerCase()
    return tagged.filter((e) => kinds.includes(e.kind) &&
      (!needle || (e.message || '').toLowerCase().includes(needle)))
  }, [tagged, kinds, q])

  useEffect(() => {
    if (follow && box.current) box.current.scrollTop = box.current.scrollHeight
  }, [shown.length, follow, running])

  function toggle(k) {
    setKinds((list) => (list.includes(k) ? list.filter((x) => x !== k) : [...list, k]))
  }

  return (
    <>
      <div className="logwrap">
        <div className="logbar">
          <span className="lbl"><IcoFilter /> levels</span>
          {KIND_ORDER.filter((k) => counts[k]).map((k) => (
            <button key={k} className={'lvchip' + (kinds.includes(k) ? ' on' : '')}
              onClick={() => toggle(k)} title={'Show/hide ' + KIND_LABEL[k] + ' lines'}>
              {KIND_LABEL[k]}<span className="n">{counts[k]}</span>
            </button>
          ))}
          <div className="spacer" />
          <SearchBox value={q} onChange={setQ} placeholder="Filter lines…" />
          <Toggle checked={follow} onChange={setFollow} label="Follow" title="Scroll to the newest line" />
          <button className="btn sm" onClick={onDownload} title="Download the unfiltered log">
            <IcoDownload /> Raw log
          </button>
        </div>
        <div className="ev-log workspace" ref={box}
          onScroll={(e) => {
            const el = e.currentTarget
            const atBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 40
            if (atBottom !== follow) setFollow(atBottom)
          }}>
          {shown.length === 0 && (
            <div className="row muted" style={{ padding: '8px 12px' }}>
              {events.length === 0
                ? (running ? 'Waiting for the engine to say something…' : 'No log output recorded.')
                : 'Every line is filtered out — enable a level above.'}
            </div>
          )}
          {shown.map((e) => (
            <div className="row" key={e.id}>
              <span className="ts">{e.ts ? new Date(e.ts).toLocaleTimeString() : ''}</span>
              <span className={'msg lv-' + e.kind}>{e.message}</span>
            </div>
          ))}
          {running && <div className="row"><span className="msg muted"><Spinner /> listening…</span></div>}
        </div>
      </div>
      <p className="ledger-note" style={{ marginTop: 10 }}>
        {verbose === 0
          ? 'This run was launched without -v, so the engine is not emitting its baseline comparisons or suppression reasons. The Refused tab still lists every candidate the proof gate declined, and why.'
          : verbose === 1
            ? 'Verbose (-v): baseline comparisons, proof acceptances and suppression reasons are included in this stream.'
            : 'Trace (-vv): every probe and payload is included in this stream.'}
      </p>
    </>
  )
}

/* ------------------------------------------------------------- findings -- */

function FindingsView({ rows, scanId, running }) {
  const [openId, setOpenId] = useState(null)
  if (!rows) return <div className="muted"><Spinner /> loading findings…</div>
  if (!rows.length) {
    return running
      ? <div className="empty">No findings proven yet — each one appears here as
        soon as the gate accepts it, without waiting for the run to finish.</div>
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
            {f.proof && (
              <div className="proofbox">
                <IcoShield />
                <div>
                  <div className="proof-lbl">What proves this</div>
                  <div className="proof-txt mono">{f.proof}</div>
                </div>
              </div>
            )}
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

/* ------------------------------------------------------------ suppressed -- */

function SuppressedView({ rows, running }) {
  const [q, setQ] = useState('')
  if (!rows) return <div className="muted"><Spinner /> loading ledger…</div>
  const needle = q.trim().toLowerCase()
  const shown = needle
    ? rows.filter((r) => [r.title, r.module, r.reason, r.cls]
      .some((v) => (v || '').toLowerCase().includes(needle)))
    : rows
  return (
    <>
      <p className="ledger-note">
        Candidates the proof gate refused. Each one was observed, and each one
        failed the evidentiary bar for its class — no marker, a negative control
        that was not clean, or no proof supplied at all. They are listed here, not
        as findings, so a suppression is reviewable: an empty ledger and a broken
        scanner look identical from the findings list alone.
      </p>
      <div className="toolbar">
        <SearchBox value={q} onChange={setQ} placeholder="Filter by module, title or reason…" />
        <div className="spacer" />
        <span className="muted" style={{ fontSize: 12.5 }}>{shown.length} of {rows.length}</span>
      </div>
      {rows.length === 0 ? (
        <div className="empty">{running
          ? 'Nothing refused yet. Candidates land here as the engine evaluates them.'
          : 'The proof gate accepted or never evaluated anything — no candidates were refused on this scan.'}</div>
      ) : (
        <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
          <table className="vt">
            <thead>
              <tr><th>Module</th><th>Class</th><th>Candidate</th><th>Why it was refused</th></tr>
            </thead>
            <tbody>
              {shown.map((r) => (
                <tr key={r.id}>
                  <td className="mono">{r.module}</td>
                  <td className="muted mono">{r.cls}</td>
                  <td>{r.title}</td>
                  <td className="reason"><span className="why">{r.reason}</span></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </>
  )
}
