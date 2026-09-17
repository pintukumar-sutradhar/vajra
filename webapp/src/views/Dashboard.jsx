import React, { useEffect, useState } from 'react'
import { api } from '../api.js'
import { Empty, ScanStatus } from '../components.jsx'
import { IcoTarget, IcoScan, IcoFindings, IcoEngine, IcoShield, IcoDoc, IcoPlus, IcoGauge } from '../icons.jsx'

const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info']
const SEV_COLOR = { critical: '#ff1744', high: '#ff5252', medium: '#ffb300', low: '#4fc3f7', info: '#55546e' }

function tier(score) {
  if (score <= 24) return ['LOW', 't-low']
  if (score <= 49) return ['MODERATE', 't-medium']
  if (score <= 74) return ['HIGH', 't-high']
  return ['CRITICAL', 't-critical']
}

/* ------- SVG semicircle gauge (0..100) ------- */
function Gauge({ value }) {
  const R = 90
  const LEN = Math.PI * R
  const frac = Math.max(0, Math.min(100, value)) / 100
  const d = `M 20 112 A ${R} ${R} 0 0 1 200 112`
  return (
    <div className="gauge-wrap">
      <svg width="218" height="120" viewBox="0 0 220 120">
        <defs>
          <linearGradient id="gaugeGrad" x1="0" y1="0" x2="1" y2="0">
            <stop offset="0" stopColor="#7c3aed" />
            <stop offset="0.62" stopColor="#c084fc" />
            <stop offset="1" stopColor="#e879f9" />
          </linearGradient>
        </defs>
        <path d={d} fill="none" stroke="rgba(124,58,237,0.16)" strokeWidth="16" strokeLinecap="round" />
        {value > 0 && (
          <path d={d} fill="none" stroke="url(#gaugeGrad)" strokeWidth="16" strokeLinecap="round"
            strokeDasharray={`${LEN} ${LEN}`} strokeDashoffset={LEN * (1 - frac)} />
        )}
      </svg>
      <div className="gauge-core">
        <div className="g-num">{Math.round(value)}</div>
        <div className="g-lbl">Exposure index</div>
      </div>
      <div className="gauge-tier"><span className={'g-tier ' + tier(value)[1]}>{tier(value)[0]}</span></div>
    </div>
  )
}

function Donut({ sev }) {
  const total = SEV_ORDER.reduce((n, s) => n + (sev[s] || 0), 0)
  if (!total) return <Empty text="No open findings yet" />
  let acc = 0
  const segs = []
  SEV_ORDER.forEach((s) => {
    const c = sev[s] || 0
    if (c) {
      const pct = c / total * 100
      segs.push(`${SEV_COLOR[s]} ${acc.toFixed(2)}% ${(acc + pct).toFixed(2)}%`)
      acc += pct
    }
  })
  return (
    <div className="donut-shell">
      <div className="donut-hole">
        <div className="donut" style={{ width: 150, height: 150, background: `conic-gradient(${segs.join(', ')})` }} />
        <div className="dnum"><b>{total}</b><span>open</span></div>
      </div>
      <div className="dlegend">
        {SEV_ORDER.map((s) => (
          <div className="row" key={s}>
            <i style={{ background: SEV_COLOR[s] }} />
            <span className="lb">{s}</span>
            <span className="cv">{sev[s] || 0}</span>
          </div>
        ))}
      </div>
    </div>
  )
}

function Trend({ data }) {
  const days = Object.entries(data).sort(([a], [b]) => a.localeCompare(b))
  if (!days.length) return <Empty text="No findings recorded yet" />
  const max = Math.max(1, ...days.map(([, n]) => n))
  const today = days[days.length - 1][0]
  return (
    <div className="trend">
      {days.map(([day, n]) => (
        <div className={'tcol' + (day === today ? ' today' : '')} key={day} title={`${day}: ${n} finding${n === 1 ? '' : 's'}`}>
          <span className="nv">{n}</span>
          <div className="tbar" style={{ height: Math.max(4, Math.round(n / max * 130)) + 'px' }} />
          <div className="dl">{day.slice(5).replace('-', '/')}</div>
        </div>
      ))}
    </div>
  )
}

function Bars({ rows }) {
  if (!rows.length) return <Empty text="Nothing to show yet" />
  const max = Math.max(1, ...rows.map((r) => r.count || r.value || 0))
  return (
    <div className="bars">
      {rows.map((r, i) => (
        <div className="row" key={i}>
          <span className="lb" title={r.label}>{r.label}</span>
          <div className="trak"><i className={r.fill || 'fill-violet'}
            style={{ width: Math.max(3, Math.round((r.count || r.value || 0) / max * 100)) + '%' }} /></div>
          <span className="cv">{r.count !== undefined ? r.count : r.value}</span>
        </div>
      ))}
    </div>
  )
}

function TargetRow({ t }) {
  const total = Math.max(1, t.critical + t.high + t.medium)
  return (
    <div className="trow">
      <div className="row">
        <span className="addr" title={t.address}>{t.address}</span>
        <span className="cv" style={{ width: 'auto' }}>
          <span className="rank-sev">
            {t.critical > 0 && <b className="cr">{t.critical}C</b>}
            {t.high > 0 && <b className="hi">{t.high}H</b>}
            {t.medium > 0 && <b className="md">{t.medium}M</b>}
          </span>
        </span>
        <span className={'risk-tag ' + (t.risk <= 49 ? 'r-medium' : t.risk <= 74 ? 'r-high' : 'r-critical')}>risk {t.risk}</span>
      </div>
      <div className="stack">
        {t.critical > 0 && <i className="fill-critical" style={{ width: 100 * t.critical / total + '%' }} />}
        {t.high > 0 && <i className="fill-high" style={{ width: 100 * t.high / total + '%' }} />}
        {t.medium > 0 && <i className="fill-medium" style={{ width: 100 * t.medium / total + '%' }} />}
      </div>
    </div>
  )
}

function Kpi({ icon, num, label, sub, to }) {
  return (
    <div className={'kpi-tile' + (to ? ' clickable' : '')} onClick={to ? () => { window.location.hash = '#/' + to } : undefined}>
      <div className="kic">{icon}</div>
      <div className="knum">{num}</div>
      <div className="klbl">{label}</div>
      {sub && <div className="ksub">{sub}</div>}
    </div>
  )
}

export default function Dashboard() {
  const [d, setD] = useState(null)
  const [err, setErr] = useState('')

  useEffect(() => {
    let on = true
    const load = () => {
      api('/v1/dashboard').then((r) => { if (on) setD(r) }).catch((e) => { if (on) setErr(e.message) })
    }
    load()
    const t = setInterval(load, 15000)
    return () => { on = false; clearInterval(t) }
  }, [])

  if (err) return <div className="muted">{err}</div>
  if (!d) return <div className="muted">Loading dashboard…</div>

  const c = d.counts || {}
  const sev = d.open_by_severity || {}
  const fbs = d.findings_by_status || {}
  const fixed = fbs.fixed || 0
  const byMod = (d.top_modules || []).map((m) => ({
    label: String(m.module).split('.').pop(), count: m.count,
  }))
  const scanBars = []
  const scansByStatus = d.scans_by_status || {}
  const SCAN_META = [
    ['running', 'fill-violet'], ['completed', 'fill-ok'], ['paused', 'fill-warn'],
    ['failed', 'fill-danger'], ['canceled', 'fill-muted'], ['pending', 'fill-muted'],
    ['queued', 'fill-muted'],
  ]
  SCAN_META.forEach(([s, fill]) => {
    if ((scansByStatus[s] || 0) > 0) scanBars.push({ label: s, count: scansByStatus[s], fill })
  })
  const scans14 = (d.scans_last_14d ? Object.values(d.scans_last_14d).reduce((a, b) => a + (b || 0), 0) : 0)

  return (
    <>
      <div className="dash-head">
        <div>
          <h1>Security overview</h1>
          <div className="sub">Attack-surface posture, scan activity and top risk across in-scope assets</div>
        </div>
        <div className="dash-actions">
          <button className="btn" onClick={() => { window.location.hash = '#/targets' }}><IcoPlus /> New target</button>
          <button className="btn primary" onClick={() => { window.location.hash = '#/engines' }}><IcoScan /> Launch scan</button>
        </div>
      </div>

      <div className="dash-hero">
        <div className="card gauge-card">
          <Gauge value={d.risk_score || 0} />
          <div className="gauge-sub">
            <div className="gs"><b>{d.security_score || 100}%</b><span>security</span></div>
            <div className="gs"><b>{c.open_findings || 0}</b><span>open</span></div>
            <div className="gs"><b>{c.critical_high || 0}</b><span>crit/high</span></div>
          </div>
        </div>

        <div className="kpi-grid">
          <Kpi icon={<IcoTarget />} num={c.targets || 0} label="Targets in scope" sub="tracked assets" to="targets" />
          <Kpi icon={<IcoScan />} num={c.scans || 0} label="Scans run" sub={scans14 + ' in the last 14 days'} to="scans" />
          <Kpi icon={<IcoFindings />} num={c.findings || 0} label="Total findings" sub={(c.open_findings || 0) + ' open · ' + fixed + ' fixed'} to="findings" />
          <Kpi icon={<IcoEngine />} num={c.active_scans || 0} label="Active scans" sub={c.active_scans ? 'running now' : 'queue idle'} to="scans" />
          <Kpi icon={<IcoShield />} num={c.critical_high || 0} label="Critical / high" sub={'of ' + (c.open_findings || 0) + ' open findings'} to="findings" />
          <Kpi icon={<IcoDoc />} num={c.suppressed || 0} label="Gate-suppressed" sub="candidates refused by proof gate" to="audit" />
        </div>
      </div>

      <div className="dash-grid g2">
        <div className="dash-card">
          <h3>Open findings by severity</h3>
          <div className="card-sub">Live distribution across all targets</div>
          <Donut sev={sev} />
        </div>
        <div className="dash-card">
          <h3>Findings · last 14 days</h3>
          <div className="card-sub">New findings proven per day (today highlighted)</div>
          <Trend data={d.findings_14d || {}} />
        </div>
      </div>

      <div className="dash-grid g3">
        <div className="dash-card">
          <h3>Scan activity</h3>
          <div className="card-sub">All-time scans by status</div>
          <Bars rows={scanBars} />
        </div>
        <div className="dash-card">
          <h3>Top risk targets</h3>
          <div className="card-sub">Weighted by open critical / high / medium</div>
          {(!d.top_targets || !d.top_targets.length)
            ? <Empty text="No scoring yet — scans have not produced findings" />
            : d.top_targets.map((t) => <TargetRow key={t.id} t={t} />)}
        </div>
        <div className="dash-card">
          <h3>Top attack surface</h3>
          <div className="card-sub">Findings grouped by source module</div>
          <Bars rows={byMod} />
        </div>
      </div>

      <div className="dash-card" style={{ padding: 0 }}>
        <div style={{ padding: '16px 18px 4px' }}>
          <h3>Recent activity</h3>
          <div className="card-sub">Latest scans across all engines — click to open</div>
        </div>
        {(!d.activity || !d.activity.length)
          ? <div style={{ padding: '0 18px 18px' }}><Empty text="No scans yet — launch your first scan" /></div>
          : (
            <div className="activity" style={{ padding: '0 12px 12px' }}>
              {d.activity.map((s) => {
                const live = ['pending', 'queued', 'running'].includes(s.status)
                const done = s.status === 'completed'
                const fail = s.status === 'failed' || s.status === 'canceled'
                return (
                  <div className="act-row" key={s.id} onClick={() => { window.location.hash = '#/scans/' + s.id }}>
                    <div className={'act-ic' + (done ? ' done' : fail ? ' fail' : '')}>
                      {live ? <IcoScan /> : done ? <IcoShield /> : <IcoGauge />}
                    </div>
                    <div className="act-main">
                      <div className="act-tgt">{s.target || '(no target)'}</div>
                      <div className="act-meta">
                        <span className="mono">{s.engine}</span>
                        {s.profile ? ' · ' + s.profile : ''}
                        {live ? ' · ' + (s.progress || 0) + '%' : ''}
                        {' · ' + (s.findings || 0) + ' finding' + ((s.findings || 0) === 1 ? '' : 's')}
                      </div>
                    </div>
                    <div className="act-right">
                      {live
                        ? <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}><span className="pulse" /><ScanStatus value={s.status} /></div>
                        : <ScanStatus value={s.status} />}
                      <div className="t">{new Date(s.created_at).toLocaleString()}</div>
                    </div>
                  </div>
                )
              })}
            </div>
          )}
      </div>
    </>
  )
}