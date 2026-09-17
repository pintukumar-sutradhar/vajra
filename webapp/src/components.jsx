import React, { createContext, useCallback, useContext, useEffect, useRef, useState } from 'react'
import { IcoClose, IcoLogo } from './icons.jsx'
import { getBrand } from './api.js'

/* ---------- pills ---------- */
export function Pill({ className, children }) {
  return <span className={'pill ' + (className || '')}>{children}</span>
}
export function Severity({ value }) {
  const v = (value || 'info').toLowerCase()
  return <Pill className={'sev-' + (v in { critical: 1, high: 1, medium: 1, low: 1, info: 1 } ? v : 'info')}>{v}</Pill>
}
export function Confidence({ value }) {
  const v = (value || 'tentative').toLowerCase()
  const m = { certain: 'ci-certain', firm: 'ci-firm', tentative: 'ci-tentative' }
  const c = m[v] || 'ci-tentative'
  return <Pill className={c}>{v}</Pill>
}
export function Status({ value }) {
  return <Pill className={'st-' + value}>{value.replace('-', ' ')}</Pill>
}
export function ScanStatus({ value }) {
  return <Pill className={'scan-' + value}>{value}</Pill>
}
export function ConfidenceLabel({ value }) {
  return <Pill className={'ci-' + (value || 'tentative')}>{(value || 'tentative')}</Pill>
}

/* ---------- logo ---------- */
export function Logo({ size }) {
  const b = getBrand()
  if (b.logo_svg) {
    const html = b.logo_svg.replace(/width='64' height='64'/, `width='${size || 42}' height='${size || 42}'`)
    return <span dangerouslySetInnerHTML={{ __html: html }} />
  }
  return <IcoLogo />
}

/* ---------- modal ---------- */
export function Modal({ title, onClose, children, foot, wide }) {
  useEffect(() => {
    const h = (e) => { if (e.key === 'Escape') onClose() }
    window.addEventListener('keydown', h)
    return () => window.removeEventListener('keydown', h)
  }, [onClose])
  return (
    <div className="modal-backdrop" onMouseDown={(e) => { if (e.target === e.currentTarget) onClose() }}>
      <div className="modal" style={wide ? { maxWidth: 820 } : {}}>
        <div className="mhead">
          <h2>{title}</h2>
          <button className="btn sm" onClick={onClose} aria-label="close"><IcoClose /></button>
        </div>
        <div className="mbody">{children}</div>
        {foot && <div className="mfoot">{foot}</div>}
      </div>
    </div>
  )
}

/* ---------- toasts ---------- */
const ToastCtx = createContext(() => {})
export function useToast() { return useContext(ToastCtx) }

export function ToastHost({ children }) {
  const [toasts, setToasts] = useState([])
  const id = useRef(0)
  const push = useCallback((msg, kind, timeout = 5000) => {
    const n = ++id.current
    setToasts((t) => [...t, { id: n, msg, kind }])
    setTimeout(() => setToasts((t) => t.filter((x) => x.id !== n)), timeout)
  }, [])
  const api = useCallback(async (fn) => {
    try {
      const r = await fn()
      push('ok', 3500)
      return r
    } catch (e) {
      push(e.message, 'err', 8000)
      throw e
    }
  }, [push])
  const ctx = { push, api }
  return (
    <ToastCtx.Provider value={ctx}>
      {children}
      <div className="toasts">
        {toasts.map((t) => (
          <div key={t.id} className={'toast ' + (t.kind === 'err' ? 'err' : t.kind === 'ok' ? 'ok' : '')}>{t.msg}</div>
        ))}
      </div>
    </ToastCtx.Provider>
  )
}

/* ---------- small bits ---------- */
export function Empty({ text, icon }) {
  return <div className="empty"><div className="big">{icon || '☁'}</div>{text}</div>
}
export function Spinner() {
  return <span className="spin" style={{ display: 'inline-block' }} />
}
export function Elapsed({ at, done }) {
  const [, force] = useState(0)
  useEffect(() => {
    if (done) return
    const t = setInterval(() => force((x) => x + 1), 20000)
    return () => clearInterval(t)
  }, [done])
  const s = at ? Math.max(0, (Date.now() - new Date(at).getTime()) / 1000) : 0
  const fmt = (x) => (x >= 60 ? Math.floor(x / 60) + 'm' : Math.floor(x) + 's')
  return <span className="muted">{s < 60 && s > 0 ? fmt(s) : s >= 60 ? fmt(s) : '—'} {done ? '' : 'ago'}</span>
}

/* ---------- progress ---------- */
/* `tone` switches the fill: paused runs are amber so a stopped-but-live scan
   never reads as "still working". */
export function ProgressBar({ value, tone, large }) {
  const pct = Math.max(0, Math.min(100, Number(value) || 0))
  return (
    <div className={'progress' + (large ? ' lg' : '') + (tone ? ' tone-' + tone : '')}>
      <i style={{ width: pct + '%' }} />
    </div>
  )
}

export function StatTile({ label, value, sub, tone, onClick }) {
  return (
    <div className={'statcard kpi stat-tile' + (onClick ? ' clickable' : '')}
      onClick={onClick} role={onClick ? 'button' : undefined} tabIndex={onClick ? 0 : undefined}
      onKeyDown={onClick ? (e) => { if (e.key === 'Enter') onClick() } : undefined}>
      <div className={'num' + (tone ? ' tone-' + tone : '')}>{value}</div>
      <div className="lbl">{label}</div>
      {sub && <div className="stat-sub">{sub}</div>}
    </div>
  )
}

/* ---------- tabs ---------- */
export function Tabs({ tabs, value, onChange }) {
  return (
    <div className="toolbar tabs" role="tablist">
      {tabs.map((t) => (
        <button key={t.id} role="tab" aria-selected={value === t.id}
          className={'btn ' + (value === t.id ? 'primary' : '')}
          onClick={() => onChange(t.id)} disabled={t.disabled}>
          {t.icon}{t.label}
          {t.count !== undefined && t.count !== null && (
            <span className={'tab-count' + (t.tone ? ' tone-' + t.tone : '')}>{t.count}</span>
          )}
        </button>
      ))}
    </div>
  )
}

/* ---------- toggle ---------- */
export function Toggle({ checked, onChange, label, title }) {
  return (
    <label className="switch" title={title}>
      <input type="checkbox" checked={!!checked} onChange={(e) => onChange(e.target.checked)} />
      <span className="slider" />
      {label && <span className="switch-label">{label}</span>}
    </label>
  )
}

/* ---------- confirm ---------- */
/* Destructive actions ask first. `note` carries the reassurance the operator
   needs before pulling the trigger (what survives the action). */
export function ConfirmDialog({ title, body, note, confirmLabel, tone, busy, onConfirm, onClose }) {
  return (
    <Modal title={title} onClose={onClose}
      foot={<>
        <button className="btn" onClick={onClose} disabled={busy}>Cancel</button>
        <button className={'btn ' + (tone === 'danger' ? 'danger' : 'primary')}
          onClick={onConfirm} disabled={busy}>
          {busy ? 'Working…' : (confirmLabel || 'Confirm')}
        </button>
      </>}>
      <div>{body}</div>
      {note && <div className="confirm-note">{note}</div>}
    </Modal>
  )
}

/* ---------- search ---------- */
export function SearchBox({ value, onChange, placeholder }) {
  return (
    <input type="text" className="searchbox" value={value} placeholder={placeholder || 'Search…'}
      onChange={(e) => onChange(e.target.value)} />
  )
}
