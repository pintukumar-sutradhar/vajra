import React, { useState } from 'react'
import { api } from '../api.js'
import { Logo } from '../components.jsx'

/* Forced password change: shown when a session is valid but the account must
   set a new password (seeded default admin, or an admin-issued reset). The
   platform is unusable until it succeeds, by design. */
export default function PasswordChange({ user, onDone }) {
  const [cur, setCur] = useState('')
  const [pass, setPass] = useState('')
  const [confirm, setConfirm] = useState('')
  const [show, setShow] = useState(false)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  async function submit(e) {
    e.preventDefault()
    if (pass.length < 10) { setError('Passwords must be at least 10 characters.'); return }
    if (pass !== confirm) { setError('New password and confirmation do not match.'); return }
    setBusy(true); setError('')
    try {
      const r = await api('/v1/auth/password', {
        method: 'POST', body: { current_password: cur, new_password: pass } })
      onDone(r)
    } catch (e2) {
      setError(e2.message || 'Could not change the password')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="login-wrap">
      <div className="login-orb o1" />
      <div className="login-orb o3" />
      <div className="login-grid" />
      <div className="login-stage">
        <section className="login-pane">
          <div className="login-brand">
            <Logo size={52} />
            <div>
              <div className="bname">New password</div>
            </div>
          </div>
          <h1 className="login-head">Welcome, {user.display_name || user.username}.</h1>
          <p className="login-sub">
            This account is using a temporary or default password. Choose a new
            one before continuing — it unlocks the workspace.
          </p>
        </section>
        <section className="login-pane login-formpane">
          <form className="login-form" onSubmit={submit} noValidate>
            <h2 className="form-title">Set a new password</h2>
            <p className="form-sub">At least 10 characters</p>
            {error && <div className="errorbox">{error}</div>}
            <div className="field">
              <label htmlFor="pc-cur">Current password</label>
              <div className="inrow">
                <span className="inicon">◉</span>
                <input id="pc-cur" type="password" value={cur}
                  onChange={(e) => setCur(e.target.value)}
                  autoComplete="current-password" autoFocus />
              </div>
            </div>
            <div className="field">
              <label htmlFor="pc-new">New password</label>
              <div className="inrow">
                <span className="inicon">⌁</span>
                <input id="pc-new" type={show ? 'text' : 'password'}
                  value={pass}
                  onChange={(e) => setPass(e.target.value)}
                  placeholder="••••••••••" autoComplete="new-password" />
                <button type="button" className="in-eye" tabIndex={-1}
                  onClick={() => setShow((s) => !s)} aria-label="toggle password">
                  {show ? '◐' : '◍'}
                </button>
              </div>
            </div>
            <div className="field">
              <label htmlFor="pc-confirm">Confirm new password</label>
              <div className="inrow">
                <span className="inicon">✓</span>
                <input id="pc-confirm" type={show ? 'text' : 'password'}
                  value={confirm}
                  onChange={(e) => setConfirm(e.target.value)}
                  placeholder="••••••••••" autoComplete="new-password" />
              </div>
            </div>
            <button className="btn primary btn-block" disabled={busy}>
              {busy ? 'Updating…' : 'Set password & continue'}
            </button>
          </form>
          <div className="login-foot">Authorized use only.</div>
        </section>
      </div>
    </div>
  )
}