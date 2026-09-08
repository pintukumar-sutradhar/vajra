import React, { useCallback, useEffect, useState } from 'react'
import { createRoot } from 'react-dom/client'
import './theme.css'
import { api, loadBrand, token, getBrand } from './api.js'
import { ToastHost, useToast, Logo } from './components.jsx'
import { IcoGauge, IcoTarget, IcoScan, IcoFindings, IcoEngine, IcoOut } from './icons.jsx'
import Login from './views/Login.jsx'
import Dashboard from './views/Dashboard.jsx'
import Targets from './views/Targets.jsx'
import Engines from './views/Engines.jsx'
import Scans from './views/Scans.jsx'
import ScanDetail from './views/ScanDetail.jsx'
import Findings from './views/Findings.jsx'

const NAV = [
  { id: 'dashboard', label: 'Dashboard', icon: <IcoGauge /> },
  { id: 'targets', label: 'Targets', icon: <IcoTarget /> },
  { id: 'scans', label: 'Scans', icon: <IcoScan /> },
  { id: 'engines', label: 'Engines', icon: <IcoEngine /> },
  { id: 'findings', label: 'Findings', icon: <IcoFindings /> },
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

  function login(user) {
    setUser(user)
    nav('dashboard')
  }

  if (!checked) return <div className="login-wrap"><div className="muted">Loading…</div></div>
  if (!user) return <Login onLogin={login} />

  async function logout() {
    try { await api('/v1/auth/logout', { method: 'POST' }) } catch (e) {}
    token.clear()
    document.cookie = 'vajra_session=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/'
    setUser(null)
  }

  const page = route.page || 'dashboard'
  const active = NAV.find((n) => n.id === page)

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
          <div className="pagetitle">{active ? active.label : 'Scan'}</div>
          <div className="right">
            <span className="chip">{getProduct()}</span>
          </div>
        </div>
        <div className="content">
          {page === 'dashboard' && <Dashboard />}
          {page === 'targets' && <Targets />}
          {page === 'engines' && <Engines onScanStart={(id) => nav('scans', id)} />}
          {page === 'scans' && (route.param ? <ScanDetail id={route.param} /> : <Scans onOpen={(id) => nav('scans', id)} />)}
          {page === 'findings' && <Findings />}
        </div>
      </main>
    </div>
  )
}

function getProduct() {
  return getBrand().edition || 'Professional'
}

createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <ToastHost>
      <Shell />
    </ToastHost>
  </React.StrictMode>
)