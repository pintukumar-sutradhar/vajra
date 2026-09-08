import React, { useEffect, useState } from 'react'
import { api } from '../api.js'
import { ScanStatus, Empty, useToast } from '../components.jsx'
import { IcoRefreshCw } from '../icons.jsx'

export default function Audit() {
  const [rows, setRows] = useState(null)
  const [limit, setLimit] = useState(100)
  const shout = useToast()

  async function load() {
    try {
      const r = await api('/v1/audit?limit=' + limit)
      setRows(r)
    } catch (e) {
      shout.push(e.message, 'err')
    }
  }
  useEffect(load, [limit])

  return (
    <>
      <div className="toolbar">
        <h2 style={{ fontSize: 15, marginRight: 'auto' }}>Audit log</h2>
        <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
          <select value={limit} onChange={(e) => setLimit(+e.target.value)} style={{ width: 100 }}>
            <option value={50}>50</option>
            <option value={100}>100</option>
            <option value={250}>250</option>
            <option value={500}>500</option>
          </select>
          <button className="btn" onClick={load} disabled={!rows} title="Refresh">
            <IcoRefreshCw />
          </button>
        </div>
      </div>

      {!rows
        ? <div className="muted"><Spinner /> loading…</div>
        : rows.length === 0
          ? <Empty icon="📋" text="No audit events yet." />
          : (
            <div className="card">
              <table className="vt">
                <thead>
                  <tr><th>When</th><th>Actor</th><th>Action</th><th>Target</th><th>Detail</th></tr>
                </thead>
                <tbody>
                  {rows.map((r) => (
                    <tr key={r.id}>
                      <td className="mono muted">{new Date(r.ts).toLocaleString()}</td>
                      <td className="mono">{r.actor || 'system'}</td>
                      <td><code className="mono" style={{ fontSize: 11 }}>{r.action}</code></td>
                      <td className="mono muted">{r.target_type || '—'}:{r.target_id || ''}</td>
                      <td className="mono" style={{ maxWidth: 360, whiteSpace: 'pre-wrap', fontSize: 11 }}>
                        {JSON.stringify(r.detail, null, 2)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
    </>
  )
}

function Spinner() { return <span className="spin" style={{ display: 'inline-block' }} /> }