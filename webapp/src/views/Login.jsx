import React, { useState } from 'react'
import { api, token } from '../api.js'
import { Logo } from '../components.jsx'

export default function Login({ onLogin }) {
  const [username, setUsername] = useState('admin')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  async function submit(e) {
    e.preventDefault()
    setBusy(true); setError('')
    try {
      const r = await api('/v1/auth/login', { method: 'POST', body: { username, password } })
      token.set(r.token)
      onLogin(r.user)
    } catch (e2) {
      setError(e2.message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="login-wrap">
      <div className="card login-card">
        <form onSubmit={submit}>
          <div className="login-brand">
            <Logo size={44} />
            <div>
              <div className="bname">VAJRA</div>
              <div className="bedition">offensive security platform</div>
            </div>
          </div>
          {error && <div className="errorbox">{error}</div>}
          <div className="field">
            <label>Username</label>
            <input value={username} onChange={(e) => setUsername(e.target.value)} autoFocus />
          </div>
          <div className="field">
            <label>Password</label>
            <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} />
          </div>
          <button className="btn primary" style={{ width: '100%', justifyContent: 'center' }} disabled={busy}>
            {busy ? 'Signing in…' : 'Sign in'}
          </button>
          <div className="hint" style={{ marginTop: 14, textAlign: 'center' }}>
            Every scan requires an explicit authorized-scope reference.
          </div>
        </form>
      </div>
    </div>
  )
}