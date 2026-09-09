import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { createRoot } from 'react-dom/client'
import './theme.css'
import { api, loadBrand, token, getBrand } from './api.js'
import { ToastHost, useToast, Logo } from './components.jsx'
import { IcoGauge, IcoTarget, IcoScan, IcoFindings, IcoEngine, IcoOut, IcoDoc } from './icons.jsx'
import Login from './views/Login.jsx'
import Dashboard from './views/Dashboard.jsx'
import Targets from './views/Targets.jsx'
import Engines from './views/Engines.jsx'
import Scans from './views/Scans.jsx'
import ScanDetail from './views/ScanDetail.jsx'
import Findings from './views/Findings.jsx'
import Audit from './views/Audit.jsx'

const NAV = [
  { id: 'dashboard', label: 'Dashboard', icon: <IcoGauge /> },
  { id: 'targets', label: 'Targets', icon: <IcoTarget /> },
  { id: 'scans', label: 'Scans', icon: <IcoScan /> },
  { id: 'engines', label: 'Engines', icon: <IcoEngine /> },
  { id: 'findings', label: 'Findings', icon: <IcoFindings /> },
  { id: 'audit', label: 'Audit', icon: <IcoDoc /> },
]

const HOTKEYS = [
  ['Ctrl+K', 'Command palette'],
  ['G → D', 'Go to Dashboard'],
  ['G → T', 'Go to Targets'],
  ['G → S', 'Go to Scans'],
  ['G → E', 'Go to Engines'],
  ['G → F', 'Go to Findings'],
  ['N → T', 'New target'],
  ['N → S', 'Launch scan'],
  ['?', 'Show key reference'],
  ['Esc', 'Close palette / help'],
]

function readHash() {
  const h = window.location.hash.replace(/^#\/?/, '')
  if (!h) return { page: 'dashboard', param: null }
  const i = h.indexOf('/')
  if (i === -1) return { page: h, param: null }
  return { page: h.slice(0, i), param: h.slice(i + 1) }
}

function Shell() {
  const [user, setUser] = useState(null)
  const [route, setRoute] = useState(readHash)
  const [checked, setChecked] = useState(false)
  const [palette, setPalette] = useState(false)
  const [help, setHelp] = useState(false)
  const [active, setActive] = useState(0)
  const seqKey = useRef(null)
  const seqTimer = useRef(null)
  const shout = useToast()

  const nav = useCallback((page, param) => {
    window.location.hash = '/' + page + (param ? '/' + param : '')
    setRoute({ page, param })
  }, [])

  useEffect(() => {
    loadBrand().then(() => setChecked(true))
    const onHash = () => setRoute(readHash())
    window.addEventListener('hashchange', onHash)
    return () => window.removeEventListener('hashchange', onHash)
  }, [])

  useEffect(() => {
    if (!checked) return
    if (!token.get()) { setUser(null); return }
    api('/v1/auth/me').then((r) => setUser(r.user)).catch(() => {
      token.clear(); setUser(null)
    })
  }, [checked])

  const refreshActive = useCallback(async () => {
    try {
      const s = await api('/v1/scans?limit=100')
      if (Array.isArray(s)) setActive(s.filter((x) => ['pending', 'queued', 'running'].includes(x.status)).length)
    } catch (e) {}
  }, [])
  useEffect(() => {
    if (!user) return
    refreshActive()
    const t = setInterval(refreshActive, 15000)
    return () => clearInterval(t)
  }, [user, refreshActive])

  function login(u) {
    setUser(u)
    // Defer to let React unmount Login and flush DOM before we blur/focus
    setTimeout(() => {
      document.querySelectorAll('input, textarea, select').forEach(el => el.blur())
      document.body.focus()
      nav('dashboard')
    }, 0)
  }

  function pressSeq(key) {
    console.log('[pressSeq] seqKey.current=', seqKey.current, 'key=', key);
    const map = { d: 'dashboard', t: 'targets', s: 'scans', e: 'engines', f: 'findings', a: 'audit' }
    if (seqKey.current === 'g' && map[key]) {
      console.log('[pressSeq] calling nav for', map[key]);
      nav(map[key])
    }
    if (seqKey.current === 'n') {
      if (key === 't') { console.log('[pressSeq] calling nav for targets'); nav('targets') }
      if (key === 's') { console.log('[pressSeq] calling nav for engines'); nav('engines') }
    }
    clearTimeout(seqTimer.current)
    seqKey.current = null
  }

  useEffect(() => {
    console.log('[hotkey] useEffect MOUNT, route.page=', route?.page);
    function onKey(e) {
      console.log('[hotkey] keydown', e.key, 'seqKey=', seqKey.current);
      if (e.key === 'Escape') { setPalette(false); setHelp(false); return }
      const t = e.target
      const typing = t && (t.tagName === 'INPUT' || t.tagName === 'TEXTAREA' ||
        t.tagName === 'SELECT' || (t.isContentEditable === true))
      if (typing) { console.log('[hotkey] typing, ignoring'); return }
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault(); console.log('[hotkey] Ctrl+K -> palette'); setPalette((p) => !p); return
      }
      if (e.key === '?') { console.log('[hotkey] ? -> help'); setHelp((h) => !h); return }
      if (seqKey.current) { console.log('[hotkey] seqKey active, pressSeq', e.key); pressSeq(e.key); return }
      if (e.key === 'g' || e.key === 'n') {
        console.log('[hotkey] setting seqKey', e.key);
        seqKey.current = e.key
        seqTimer.current = setTimeout(() => { console.log('[hotkey] seqKey timeout'); seqKey.current = null }, 1200)
      }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [nav, route])

  if (!checked) return <div className="login-wrap"><div className="muted">Loading…</div></div>
  if (!user) return <Login onLogin={login} />

  async function logout() {
    try { await api('/v1/auth/logout', { method: 'POST' }) } catch (e) {}
    token.clear()
    document.cookie = 'vajra_session=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/'
    setUser(null)
  }

  const page = route.page || 'dashboard'
  const activeNav = NAV.find((n) => n.id === page)

  return (
    <div className="shell">
      <aside className="siderail">
        <div className="brand">
          <Logo size={38} />
          <div>
            <div className="bname">VAJRA</div>
            <div className="bedition">offensive security platform</div>
          </div>
        </div>
        <nav className="nav">
          <div className="group">Workspace</div>
          {NAV.map((n) => (
            <button key={n.id} className={'navitem' + (page === n.id ? ' active' : '')}
              onClick={() => nav(n.id)}>
              {n.icon} {n.label}
            </button>
          ))}
        </nav>
        <div className="who">
          <div className="uname">{user.display_name || user.username}</div>
          <div className="urole">{user.role}</div>
          <button className="btn sm" style={{ width: '100%', marginTop: 10 }} onClick={logout}>
            <IcoOut /> Sign out
          </button>
        </div>
      </aside>

      <main className="main">
        <div className="topbar">
          <div className="pagetitle">
            {activeNav ? activeNav.label : 'Scan'}
            <button className="btn sm" style={{ marginLeft: 12 }} onClick={() => setPalette(true)}
              title="Command palette (Ctrl+K)">⌘ Ctrl+K</button>
          </div>
          <div className="right">
            <span className={'chip' + (active > 0 ? ' chip-alive' : '')}>{active > 0 ? `⚡ ${active} active` : 'idle'}</span>
            <span className="chip">{getProduct()}</span>
          </div>
        </div>
        <div className="content">
          {page === 'dashboard' && <Dashboard />}
          {page === 'targets' && <Targets />}
          {page === 'engines' && <Engines onScanStart={(id) => nav('scans', id)} />}
          {page === 'scans' && (route.param ? <ScanDetail id={route.param} /> : <Scans onOpen={(id) => nav('scans', id)} />)}
          {page === 'findings' && <Findings />}
          {page === 'audit' && <Audit />}
        </div>
      </main>

      {palette && <Palette onClose={() => setPalette(false)} onPick={(p, param) => { setPalette(false); nav(p, param) }} />}
      {help && <HelpOverlay onClose={() => setHelp(false)} />}
    </div>
  )
}

function Palette({ onClose, onPick }) {
  const [q, setQ] = useState('')
  const [idx, setIdx] = useState(0)
  const input = useRef(null)
  const items = useMemo(() => [
    { k: 'dashboard', label: 'Dashboard', hint: 'g d', act: () => onPick('dashboard') },
    { k: 'targets', label: 'Targets — assets & scope', hint: 'g t', act: () => onPick('targets') },
    { k: 'scans', label: 'Scans — queue & history', hint: 'g s', act: () => onPick('scans') },
    { k: 'engines', label: 'Engines — launch a scan', hint: 'n s', act: () => onPick('engines') },
    { k: 'findings', label: 'Findings — triage & evidence', hint: 'g f', act: () => onPick('findings') },
    { k: 'audit', label: 'Audit — immutable activity log', hint: 'g a', act: () => onPick('audit') },
    { k: 'new target', label: 'New target → Targets', hint: 'n t', act: () => onPick('targets') },
    { k: 'launch scan', label: 'Launch scan → Engines', hint: 'n s', act: () => onPick('engines') },
  ], [onPick])
  const filtered = q ? items.filter((i) => (i.label + ' ' + i.hint + ' ' + i.k).toLowerCase().includes(q.toLowerCase())) : items

  useEffect(() => input.current && input.current.focus(), [])
  useEffect(() => setIdx(0), [q])

  function key(e) {
    if (e.key === 'ArrowDown') { e.preventDefault(); setIdx((i) => Math.min(i + 1, filtered.length - 1)) }
    else if (e.key === 'ArrowUp') { e.preventDefault(); setIdx((i) => Math.max(i - 1, 0)) }
    else if (e.key === 'Enter') { filtered[idx] && filtered[idx].act() }
    else if (e.key === 'Escape') onClose()
  }

  return (
    <div className="modal-backdrop" style={{ zIndex: 70 }} onMouseDown={(e) => { if (e.target === e.currentTarget) onClose() }}>
      <div className="palette" onKeyDown={key}>
        <input ref={input} value={q} onChange={(e) => setQ(e.target.value)}
          placeholder="Type to search… (pages, actions, hotkeys)" />
        <div className="pal-list">
          {filtered.length === 0 && <div className="muted" style={{ padding: 14 }}>No matches</div>}
          {filtered.map((i, n) => (
            <button key={i.k} className={'pal-item' + (n === idx ? ' on' : '')}
              onMouseEnter={() => setIdx(n)} onClick={() => i.act()}>
              <div>{i.label}</div>
              <span className="muted mono">{i.hint}</span>
            </button>
          ))}
        </div>
      </div>
    </div>
  )
}

function HelpOverlay({ onClose }) {
  return (
    <div className="modal-backdrop" style={{ zIndex: 70 }} onMouseDown={(e) => { if (e.target === e.currentTarget) onClose() }}>
      <div className="card" style={{ maxWidth: 440, width: '100%' }}>
        <h2 style={{ marginBottom: 14 }}>Keyboard shortcuts</h2>
        <table className="vt">
          <tbody>
            {HOTKEYS.map(([k, v]) => (
              <tr key={k}><td className="mono" style={{ whiteSpace: 'nowrap' }}>{k}</td><td className="muted">{v}</td></tr>
            ))}
          </tbody>
        </table>
        <div style={{ marginTop: 14, textAlign: 'right' }}>
          <button className="btn primary" onClick={onClose}>Close (Esc)</button>
        </div>
      </div>
    </div>
  )
}

function getProduct() {
  return getBrand().edition || getBrand().product || 'VAJRA'
}

createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <ToastHost>
      <Shell />
    </ToastHost>
  </React.StrictMode>
)