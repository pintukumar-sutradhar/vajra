const TOKEN_KEY = 'vajra.token'

export const token = {
  get: () => localStorage.getItem(TOKEN_KEY),
  set: (t) => localStorage.setItem(TOKEN_KEY, t),
  clear: () => localStorage.removeItem(TOKEN_KEY),
}

let _brand = {
  product: 'VAJRA',
  tagline: 'Offensive security platform',
  edition: 'Community',
  logo_svg: '',
  colors: {},
}

export function getBrand() { return _brand }

export async function loadBrand() {
  try {
    const r = await fetch('/api/v1/auth/brand')
    if (r.ok) _brand = await r.json()
  } catch (e) { /* offline-first: keep defaults */ }
  return _brand
}

export async function api(path, opts = {}) {
  const headers = { 'Content-Type': 'application/json', ...(opts.headers || {}) }
  if (token.get()) headers['Authorization'] = 'Bearer ' + token.get()
  const res = await fetch('/api' + path, {
    method: opts.method || 'GET',
    headers,
    body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
  })
  const ct = res.headers.get('content-type') || ''
  const data = ct.includes('application/json')
    ? await res.json().catch(() => ({}))
    : await res.text()
  if (!res.ok) {
    const detail =
      typeof data === 'object' && data && data.detail
        ? (Array.isArray(data.detail) ? data.detail.map((d) => d.msg).join('; ') : String(data.detail))
        : res.status + ' ' + res.statusText
    const err = new Error(detail)
    err.status = res.status
    throw err
  }
  return data
}

/* EventSource-over-fetch so we can send the Authorization header.
   Re-emits last event id, so the API replays from where we left off. */
export async function streamEvents(url, { onEvent, onDone, signal }) {
  try {
    const res = await fetch('/api' + url, {
      headers: token.get() ? { Authorization: 'Bearer ' + token.get() } : {},
      signal,
    })
    if (!res.ok || !res.body) throw new Error('stream failed')
    const reader = res.body.getReader()
    const decoder = new TextDecoder()
    let buf = ''
    while (true) {
      const { done, value } = await reader.read()
      if (done) break
      buf += decoder.decode(value, { stream: true })
      let idx
      while ((idx = buf.indexOf('\n\n')) !== -1) {
        const block = buf.slice(0, idx)
        buf = buf.slice(idx + 2)
        let id = null
        let data = null
        for (const line of block.split('\n')) {
          if (line.startsWith('id:')) id = parseInt(line.slice(3).trim(), 10)
          else if (line.startsWith('data:')) {
            const payload = line.slice(5).trim()
            try { data = JSON.parse(payload) } catch (e) { data = payload }
          }
        }
        if (data && data.event === 'done') {
          if (onDone) onDone(data.status)
          return
        }
        if (data) onEvent({ id, ...(typeof data === 'object' ? data : { message: data }) })
      }
    }
    onEvent({ type: 'eof' })
  } finally {
    if (onDone && signal && signal.aborted) onDone('aborted')
  }
}