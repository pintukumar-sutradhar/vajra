import React, { useEffect, useState } from 'react'
import { api } from '../api.js'
import { Severity, ScanStatus, Empty } from '../components.jsx'

function fmtCounts(map) {
  if (!map || !Object.keys(map).length) return '—'
  return Object.entries(map)
    .sort((a, b) => 'critical,high,medium,low,info'.indexOf(a[0]) - 'critical,high,medium,low,info'.indexOf(b[0]))
    .map(([k, v]) => `${k} ${v}`)
    .join(' · ')
}

export default function Dashboard() {
  const [d, setD] = useState(null)
  const [err, setErr] = useState('')

  useEffect(() => {
    api('/v1/dashboard').then(setD).catch((e) => setErr(e.message))
  }, [])

  if (err) return <div className="muted">{err}</div>
  if (!d) return <div className="muted">Loading…</div>

  const counts = d.counts || {}
  const sev = d.open_by_severity || {}

  return (
    <>
      <div className="grid c4" style={{ marginBottom: 16 }}>
        {[
          { n: counts.targets || 0, l: 'Targets' },
          { n: counts.scans || 0, l: 'Scans' },
          { n: counts.findings || 0, l: 'Findings' },
          { n: counts.open_findings || 0, l: 'Open findings' },
        ].map((x, i) => (
          <div className="statcard" key={i}>
            <div className="num">{x.n}</div>
            <div className="lbl">{x.l}</div>
          </div>
        ))}
      </div>

      <div className="grid c2" style={{ marginBottom: 16 }}>
        <div className="card">
          <h3 className="section-title" style={{ marginTop: 0 }}>Open findings by severity</h3>
          {Object.keys(sev).length === 0
            ? <Empty text="No open findings yet" />
            : (
              <div className="grid c3">
                {['critical', 'high', 'medium', 'low', 'info'].filter((s) => sev[s]).map((s) => (
                  <div key={s}>
                    <div className="num" style={{ fontSize: 24 }}>{sev[s]}</div>
                    <Severity value={s} />
                  </div>
                ))}
              </div>
            )}
        </div>
        <div className="card">
          <h3 className="section-title" style={{ marginTop: 0 }}>Recent activity</h3>
          {(!d.activity || !d.activity.length)
            ? <Empty text="No scans yet" />
            : (
              <table className="vt">
                <thead>
                  <tr><th>Engine</th><th>Target</th><th>Status</th><th>Started</th></tr>
                </thead>
                <tbody>
                  {d.activity.map((s) => (
                    <tr key={s.id}>
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
      </div>

      <div className="card">
        <h3 className="section-title" style={{ marginTop: 0 }}>Targets by kind</h3>
        <table className="vt">
          <thead><tr><th>Kind</th><th>Example</th></tr></thead>
          <tbody>
            {[{ k: 'web app', ex: 'https://app.example.com (authenticated crawl + PoC)' },
              { k: 'infrastructure', ex: '10.10.0.0/16, hostname — services, CVEs, config' },
              { k: 'active directory', ex: 'corp.example.com — AS-REP/kerberoast, ACL, ADCS' },
              { k: 'external surface', ex: 'example.com — DNS, subdomains, attack surface' }]
              .map((r, i) => (
                <tr key={i}><td><b>{r.k}</b></td><td className="muted">{r.ex}</td></tr>
              ))}
          </tbody>
        </table>
      </div>
    </>
  )
}