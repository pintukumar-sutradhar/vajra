import React, { useState } from 'react'
import { api, token, getBrand } from '../api.js'
import { Logo } from '../components.jsx'

const FEATURES = [
  { icon: '◈', title: 'All scan types', text: 'Web app, API, infrastructure, Active Directory and external attack surface — one console.' },
  { icon: '⚡', title: 'Automated exploitation', text: 'Proof-gated exploitation of confirmed issues with real PoC evidence and screenshots.' },
  { icon: '▤', title: 'Professional reporting', text: 'Branded HTML and PDF reports with executive synthesis and remediation playbooks.' },
]

export default function Login({ onLogin }) {
  const [username, setUsername] = useState('admin')
  const [password, setPassword] = useState('')
  const [show, setShow] = useState(false)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  async function submit(e) {
    e.preventDefault()
    if (!username || !password) { setError('Enter your username and password'); return }
    setBusy(true); setError('')
    try {
      const r = await api('/v1/auth/login', { method: 'POST', body: { username, password } })
      token.set(r.token)
      onLogin(r.user)
    } catch (e2) {
      setError(e2.message || 'Sign-in failed')
    } finally {
      setBusy(false)
    }
  }

  const brand = getBrand()

  return (
    <div className="login-wrap">
      <div className="login-orb o1" />
      <div className="login-orb o2" />
      <div className="login-orb o3" />
      <div className="login-grid" />
      <div className="login-stage">
        <section className="login-pane">
          <div className="login-brand">
            <Logo size={52} />
            <div>
              <div className="bname">{brand.product}</div>
              <div className="bedition">{brand.edition} · {brand.tagline}</div>
            </div>
          </div>
          <h1 className="login-head">Enterprise offensive security platform</h1>
          <p className="login-sub">
            Plan, launch and track every type of engagement — credentialed or
            unauthenticated — with automated exploitation and evidence-backed
            reporting.
          </p>
          <div className="login-feats">
            {FEATURES.map((f) => (
              <div className="feat" key={f.title}>
                <div className="feat-ic">{f.icon}</div>
                <div>
                  <div className="feat-t">{f.title}</div>
                  <div className="feat-x">{f.text}</div>
                </div>
              </div>
            ))}
          </div>
        </section>

        <section className="login-pane login-formpane">
          <form className="login-form" onSubmit={submit} noValidate>
            <h2 className="form-title">Welcome back</h2>
            <p className="form-sub">Sign in to your security workspace</p>
            {error && <div className="errorbox">{error}</div>}
            <div className="field">
              <label htmlFor="login-user">Username</label>
              <div className="inrow">
                <span className="inicon">⌁</span>
                <input id="login-user" value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  placeholder="admin" autoComplete="username" autoFocus />
              </div>
            </div>
            <div className="field">
              <label htmlFor="login-pass">Password</label>
              <div className="inrow">
                <span className="inicon">◉</span>
                <input id="login-pass" type={show ? 'text' : 'password'}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="••••••" autoComplete="current-password" />
                <button type="button" className="in-eye" tabIndex={-1}
                  onClick={() => setShow((s) => !s)} aria-label="toggle password">
                  {show ? '◐' : '◍'}
                </button>
              </div>
            </div>
            <button className="btn primary btn-block" disabled={busy}>
              {busy ? 'Signing in…' : 'Sign in'}
            </button>
            <div className="login-hint">
              Evaluation build — default credentials <code>admin / admin</code>
            </div>
          </form>
          <div className="login-foot">
            Authorized use only. Every scan requires an explicit authorized-scope
            reference.
          </div>
        </section>
      </div>
    </div>
  )
}