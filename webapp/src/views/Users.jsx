import React, { useEffect, useState } from 'react'
import { api } from '../api.js'
import { Modal, Pill, useToast } from '../components.jsx'
import { IcoUser } from '../icons.jsx'

const ROLES = ['admin', 'analyst', 'auditor']
const ROLE_HINT = {
  admin: 'full platform control — users, targets, scans, settings',
  analyst: 'run scans and triage findings',
  auditor: 'read-only: reports, findings, audit log',
}

function Role({ value }) {
  const cls = value === 'admin' ? 'ci-certain' : value === 'auditor' ? 'ci-tentative' : 'ci-firm'
  return <Pill className={cls}>{value}</Pill>
}

export default function Users() {
  const [rows, setRows] = useState(null)
  const [createOpen, setCreateOpen] = useState(false)
  const [edit, setEdit] = useState(null)
  const [reset, setReset] = useState(null)
  const shout = useToast()

  function load() {
    api('/v1/auth/users?all=1').then(setRows).catch(() => setRows([]))
  }
  useEffect(load, [])

  async function createUser(body) {
    const r = await shout.api(() => api('/v1/auth/users', { method: 'POST', body }))
    shout.push(r.username + ' created', 'ok')
    setCreateOpen(false)
    load()
  }
  async function patchUser(id, body) {
    const r = await shout.api(() => api('/v1/auth/users/' + id, { method: 'PATCH', body }))
    shout.push(r.username + ' updated', 'ok')
    setEdit(null)
    load()
  }
  async function resetPassword(id, password) {
    await shout.api(() => api('/v1/auth/users/' + id + '/reset-password',
      { method: 'POST', body: { label: password } }))
    shout.push('Reset — the user must change it at next login', 'ok')
    setReset(null)
    load()
  }

  if (!rows) return null

  return (
    <>
      <div className="toolbar">
        <span className="chip">members {rows.length}</span>
        <div className="spacer" />
        <button className="btn primary" onClick={() => setCreateOpen(true)}><IcoUser /> New user</button>
      </div>

      <div className="card">
        <table className="vt">
          <thead>
            <tr>
              <th>User</th><th>Role</th><th>Status</th><th>Last sign-in</th><th></th>
            </tr>
          </thead>
          <tbody>
            {rows.length === 0 && (
              <tr><td colSpan={5} className="muted">No members yet.</td></tr>
            )}
            {rows.map((u) => (
              <tr key={u.id}>
                <td>
                  <div style={{ fontWeight: 600 }}>{u.display_name || u.username}</div>
                  <div className="muted mono" style={{ fontSize: 11.5 }}>@{u.username}{u.must_change_password ? ' · password change required' : ''}</div>
                </td>
                <td><Role value={u.role} /></td>
                <td>
                  {u.is_active
                    ? (u.locked ? <Pill className="scan-failed">locked</Pill> : <Pill className="scan-done">active</Pill>)
                    : <Pill className="scan-failed">disabled</Pill>}
                </td>
                <td className="muted" style={{ fontSize: 12 }}>
                  {u.last_login_at ? new Date(u.last_login_at).toLocaleString() : 'never'}
                </td>
                <td style={{ textAlign: 'right', whiteSpace: 'nowrap' }}>
                  <button className="btn sm" onClick={() => setEdit(u)}>Edit</button>{' '}
                  <button className="btn sm" onClick={() => setReset(u)}>Reset password</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {createOpen && <CreateModal onClose={() => setCreateOpen(false)} onSave={createUser} />}
      {edit && <EditModal user={edit} onClose={() => setEdit(null)} onSave={patchUser} />}
      {reset && <ResetModal user={reset} onClose={() => setReset(null)} onSave={resetPassword} />}
    </>
  )
}

function CreateModal({ onClose, onSave }) {
  const [username, setUsername] = useState('')
  const [displayName, setDisplayName] = useState('')
  const [role, setRole] = useState('analyst')
  const [password, setPassword] = useState('')
  const [force, setForce] = useState(true)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const shout = useToast()

  async function save(e) {
    e.preventDefault()
    if (!username || !password) { setError('Username and an initial password are required.'); return }
    setBusy(true); setError('')
    try {
      await onSave({ username, display_name: displayName, role, password, force_change: force })
    } catch (e2) { setError(e2.message); setBusy(false) }
  }

  return (
    <Modal title="Add member" onClose={onClose}
      foot={<>
        <button className="btn" onClick={onClose}>Cancel</button>
        <button className="btn primary" onClick={save} disabled={busy}>{busy ? 'Creating…' : 'Create user'}</button>
      </>}>
      <form onSubmit={save}>
        {error && <div className="errorbox">{error}</div>}
        <div className="field">
          <label>Username</label>
          <input value={username} onChange={(e) => setUsername(e.target.value)}
            placeholder="j.doe" autoComplete="off" autoFocus />
          <div className="hint">3–60 characters: letters, digits, . _ -</div>
        </div>
        <div className="field">
          <label>Display name</label>
          <input value={displayName} onChange={(e) => setDisplayName(e.target.value)}
            placeholder="Jamie Doe" autoComplete="off" />
        </div>
        <div className="field">
          <label>Role</label>
          <select value={role} onChange={(e) => setRole(e.target.value)}>
            {ROLES.map((r) => <option key={r}>{r}</option>)}
          </select>
          <div className="hint">{ROLE_HINT[role]}</div>
        </div>
        <div className="field">
          <label>Initial password</label>
          <input type="password" value={password} onChange={(e) => setPassword(e.target.value)}
            autoComplete="new-password" />
          <div className="hint">The member should change it at first login.</div>
        </div>
        <label className="switch">
          <input type="checkbox" checked={force} onChange={(e) => setForce(e.target.checked)} />
          <span className="slider" />
          <span className="switch-label">Require password change at first login</span>
        </label>
        <div style={{ display: 'none' }}><button type="submit">submit</button></div>
      </form>
    </Modal>
  )
}

function EditModal({ user, onClose, onSave }) {
  const [displayName, setDisplayName] = useState(user.display_name || '')
  const [role, setRole] = useState(user.role)
  const [isActive, setIsActive] = useState(user.is_active)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const shout = useToast()

  async function save() {
    setBusy(true); setError('')
    try {
      await onSave(user.id, { display_name: displayName, role, is_active: isActive })
    } catch (e2) { setError(e2.message); setBusy(false) }
  }

  return (
    <Modal title={'Edit @' + user.username} onClose={onClose}
      foot={<>
        <button className="btn" onClick={onClose}>Cancel</button>
        <button className="btn primary" onClick={save} disabled={busy}>{busy ? 'Saving…' : 'Save'}</button>
      </>}>
      {error && <div className="errorbox">{error}</div>}
      <div className="field">
        <label>Display name</label>
        <input value={displayName} onChange={(e) => setDisplayName(e.target.value)} />
      </div>
      <div className="field">
        <label>Role</label>
        <select value={role} onChange={(e) => setRole(e.target.value)}>
          {ROLES.map((r) => <option key={r}>{r}</option>)}
        </select>
        <div className="hint">{ROLE_HINT[role]}</div>
      </div>
      <label className="switch">
        <input type="checkbox" checked={isActive} onChange={(e) => setIsActive(e.target.checked)} />
        <span className="slider" />
        <span className="switch-label">Account active</span>
      </label>
      <div className="hint" style={{ marginTop: 8 }}>
        Disabling the account signs it out everywhere and blocks future logins.
      </div>
    </Modal>
  )
}

function ResetModal({ user, onClose, onSave }) {
  const [password, setPassword] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const shout = useToast()

  async function save() {
    if (!password) { setError('Provide the new initial password.'); return }
    setBusy(true); setError('')
    try {
      await onSave(user.id, password)
    } catch (e2) { setError(e2.message); setBusy(false) }
  }

  return (
    <Modal title={'Reset password — @' + user.username} onClose={onClose}
      foot={<>
        <button className="btn" onClick={onClose}>Cancel</button>
        <button className="btn primary" onClick={save} disabled={busy}>{busy ? 'Resetting…' : 'Set password'}</button>
      </>}>
      {error && <div className="errorbox">{error}</div>}
      <div className="field">
        <label>New initial password</label>
        <input type="password" value={password} onChange={(e) => setPassword(e.target.value)}
          autoComplete="new-password" autoFocus />
        <div className="hint">
          All active sessions are revoked. {user.username} must change this
          password at their next sign-in.
        </div>
      </div>
    </Modal>
  )
}