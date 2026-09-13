import React, { useEffect, useState } from 'react'
import { api } from '../api.js'
import { Severity, ScanStatus, Empty } from '../components.jsx'

const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info']

export default function Dashboard() {
  const [d, setD] = useState(null)
  const [engines, setEngines] = useState(null)
  const [err, setErr] = useState('')

  useEffect(() => {
    api('/v1/dashboard').then(setD).catch((e) => setErr(e.message))
    api('/v1/engines').then(setEngines).catch(() => {})
  }, [])

  if (err) return <div className="muted">{err}</div>
  if (!d) return <div className="muted">Loading…</div>

  const counts = d.counts || {}
  const sev = d.open_by_severity || {}
  const total = SEV_ORDER.reduce((n, s) => n + (sev[s] || 0), 0) || 1
  const days = d.scans_last_7d || {}
  const maxDay = Math.max(1, ...Object.values(days).map(Number))

  return (
    <>
      <div className="grid c4" style={{ marginBottom: 16 }}>
        {[
          { n: counts.targets || 0, l: 'Targets in scope' },
          { n: counts.scans || 0, l: 'Scans run' },
          { n: counts.findings || 0, l: 'Total findings' },
          { n: counts.open_findings || 0, l: 'Open findings' },
        ].map((x, i) => (
          <div className="statcard kpi" key={i}>
            <div className="num">{x.n}</div>
            <div className="lbl">{x.l}</div>
          </div>
        ))}
      </div>

      <div className="grid c2" style={{ marginBottom: 16 }}>
        <div className="card">
          <h3 className="section-title" style={{ marginTop: 0 }}>Open findings by severity</h3>
          {total === 1 && !sev.critical && !sev.high && !sev.medium && !sev.low && !sev.info
            ? <Empty text="No open findings yet" />
            : (
              <div>
                {SEV_ORDER.map((s) => (
                  <div className="sevrow" key={s}>
                    <span className="sev-lbl" style={{ color: 'var(--sev-' + s + ')' }}>{s}</span>
                    <div className="track"><i style={{
                      width: Math.round((sev[s] || 0) / total * 100) + '%',
                      background: 'linear-gradient(90deg, var(--sev-' + s + '), var(--sev-' + s + '))',
                    }} /></div>
                    <span className="sevcnt">{sev[s] || 0}</span>
                  </div>
                ))}
              </div>
            )}
        </div>

        <div className="card">
          <h3 className="section-title" style={{ marginTop: 0 }}>Scans last 7 days</h3>
          {Object.keys(days).length === 0
            ? <Empty text="No scans in the last 7 days" />
            : (
              <div className="hchart">
                {Object.entries(days).sort(([a], [b]) => a.localeCompare(b)).map(([day, n]) => (
                  <div className="hcol" key={day} title={`${day}: ${n} scan${n === 1 ? '' : 's'}`}>
                    <div className="hbar" style={{ height: Math.max(4, Math.round(n / maxDay * 100)) + '%' }}>
                      <span>{n}</span>
                    </div>
                    <div className="hday">{day.slice(5).replace('-', '/')}</div>
                  </div>
                ))}
              </div>
            )}
        </div>
      </div>

      <div className="grid c2" style={{ marginBottom: 16 }}>
        <div className="card">
          <h3 className="section-title" style={{ marginTop: 0 }}>Recent scans</h3>
          {(!d.activity || !d.activity.length)
            ? <Empty text="No scans yet" />
            : (
              <table className="vt">
                <thead>
                  <tr><th>Engine</th><th>Target</th><th>Status</th><th>Started</th></tr>
                </thead>
                <tbody>
                  {d.activity.map((s) => (
                    <tr key={s.id} style={{ cursor: 'pointer' }}
                      onClick={() => { window.location.hash = '#/scans/' + s.id }}>
                      <td className="mono">{s.engine}</td>
                      <td>{s.target}</td>
                      <td><ScanStatus value={s.status} /></td>
                      <td className="muted">{new Date(s.created_at).toLocaleString()}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
        </div>

        <div className="card">
          <h3 className="section-title" style={{ marginTop: 0 }}>Engines &amp; capabilities</h3>
          {!engines || engines.length === 0
            ? <Empty text="No engines available" />
            : engines.map((e) => (
              <div className="cap" key={e.engine_id}>
                <div className="cap-name">{e.label || e.engine_id}</div>
                <div className="cap-desc">{e.description}</div>
              </div>
            ))}
        </div>
      </div>
    </>
  )
}