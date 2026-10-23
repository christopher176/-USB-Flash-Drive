// API client for the USB Shield local agent.
// The token is held only in this tab's localStorage and is sent over the
// same-origin /api proxy, never to any remote server.

import type {
  AgentInfo, AuditRow, Device, Finding, QuarantineEntry, ScanRecord,
  ScanRequestBody, ScanEventsPage,
} from './types'

const TOKEN_KEY = 'usbshield.token'           // access token (short-lived)
const CLIENT_ID_KEY = 'usbshield.clientId'
const CLIENT_SECRET_KEY = 'usbshield.clientSecret'
const TOKEN_EXP_KEY = 'usbshield.tokenExp'
const CSRF_HEADER = 'X-USBShield-Client'
const CSRF_VALUE = 'usb-shield-web'

export class ApiError extends Error {
  status: number
  constructor(status: number, detail: string) {
    super(detail)
    this.status = status
  }
}

export interface PairResult {
  client_id: string
  client_secret: string
  access_token: string
  expires_in: number
  note: string
}

function messageFrom(status: number, body: unknown, fallback: string): string {
  if (body && typeof body === 'object' && 'detail' in (body as Record<string, unknown>)) {
    const d = (body as Record<string, unknown>).detail
    if (typeof d === 'string') return d
    return JSON.stringify(d)
  }
  return `${fallback} (HTTP ${status})`
}

export function getToken(): string { return localStorage.getItem(TOKEN_KEY) || '' }

export function setPairing(p: PairResult | null) {
  if (p) {
    localStorage.setItem(TOKEN_KEY, p.access_token)
    localStorage.setItem(CLIENT_ID_KEY, p.client_id)
    localStorage.setItem(CLIENT_SECRET_KEY, p.client_secret)
    localStorage.setItem(TOKEN_EXP_KEY, String(Date.now() + p.expires_in * 1000))
  } else {
    for (const k of [TOKEN_KEY, CLIENT_ID_KEY, CLIENT_SECRET_KEY, TOKEN_EXP_KEY]) {
      localStorage.removeItem(k)
    }
  }
}

/** Backwards-compatible admin-token connect (pairing normally preferred). */
export function setToken(t: string) {
  if (t) localStorage.setItem(TOKEN_KEY, t)
  else setPairing(null)
}

let refreshing: Promise<void> | null = null

/** Refresh the short-lived access token using the stored client credential. */
async function ensureFreshToken(): Promise<void> {
  const cid = localStorage.getItem(CLIENT_ID_KEY)
  const secret = localStorage.getItem(CLIENT_SECRET_KEY)
  if (!cid || !secret) return                       // manual admin token mode
  const exp = Number(localStorage.getItem(TOKEN_EXP_KEY) || 0)
  if (Date.now() < exp - 30_000) return             // still fresh
  refreshing ??= (async () => {
    try {
      const resp = await fetch('/api/token', {
        method: 'POST',
        headers: { [CSRF_HEADER]: CSRF_VALUE, 'Content-Type': 'application/json' },
        body: JSON.stringify({ client_id: cid, client_secret: secret }),
        credentials: 'same-origin',
      })
      if (!resp.ok) return                          // stale creds → force re-pair on next 401
      const body = (await resp.json()) as { access_token: string; expires_in: number }
      localStorage.setItem(TOKEN_KEY, body.access_token)
      localStorage.setItem(TOKEN_EXP_KEY, String(Date.now() + body.expires_in * 1000))
    } finally {
      refreshing = null
    }
  })()
  await refreshing
}

async function request<T>(
  path: string,
  opts: { method?: string; body?: unknown; token?: string | null } = {},
): Promise<T> {
  if (opts.token === undefined) await ensureFreshToken()
  const token = opts.token !== undefined ? opts.token : getToken()
  const headers: Record<string, string> = {}
  if (opts.method && opts.method !== 'GET') headers[CSRF_HEADER] = CSRF_VALUE
  if (opts.body !== undefined) headers['Content-Type'] = 'application/json'
  if (token) headers['Authorization'] = `Bearer ${token}`
  let resp: Response
  try {
    resp = await fetch(`/api${path}`, {
      method: opts.method || 'GET',
      headers,
      body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
      credentials: 'same-origin',
    })
  } catch {
    throw new ApiError(0, 'Cannot reach the local USB Shield agent. Is it running?')
  }
  if (!resp.ok) {
    // one retry after a forced refresh covers mid-flight expiry
    if (resp.status === 401 && localStorage.getItem(CLIENT_ID_KEY)) {
      localStorage.setItem(TOKEN_EXP_KEY, '0')
      await ensureFreshToken()
      if (getToken()) {
        return request<T>(path, { ...opts })
      }
    }
    let body: unknown = null
    try { body = await resp.json() } catch { /* non-JSON */ }
    throw new ApiError(resp.status, messageFrom(resp.status, body, 'Request failed'))
  }
  return (await resp.json()) as T
}

async function download(path: string, fallbackName: string): Promise<void> {
  await ensureFreshToken()
  const headers: Record<string, string> = {}
  const token = getToken()
  if (token) headers['Authorization'] = `Bearer ${token}`
  const resp = await fetch(`/api${path}`, { headers, credentials: 'same-origin' })
  if (!resp.ok) {
    let detail = `HTTP ${resp.status}`
    try { detail = messageFrom(resp.status, await resp.json(), detail) } catch { /* keep */ }
    throw new ApiError(resp.status, detail)
  }
  const dispo = resp.headers.get('content-disposition') || ''
  const match = /filename="?([^";]+)"?/.exec(dispo)
  const name = match ? match[1] : fallbackName
  const blob = await resp.blob()
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = name
  document.body.appendChild(a)
  a.click()
  a.remove()
  URL.revokeObjectURL(url)
}

export const api = {
  pair: () => request<PairResult>('/pair', { method: 'POST', token: '' }),
  info: () => request<AgentInfo>('/info'),
  drives: () => request<{ devices: Device[]; note: string }>('/drives'),
  createDemo: () => request<{ device: Device | null; warning: string }>('/devices/demo', { method: 'POST' }),
  removeDemo: () => request('/devices/demo', { method: 'DELETE' }),
  eject: (deviceId: string) =>
    request<{ ejected: boolean; message: string }>(`/devices/${encodeURIComponent(deviceId)}/eject`, { method: 'POST' }),
  startScan: (body: ScanRequestBody) =>
    request<ScanRecord>('/scans', { method: 'POST', body }),
  scan: (id: string) => request<ScanRecord>(`/scans/${encodeURIComponent(id)}`),
  scanEvents: (id: string, since: number) =>
    request<ScanEventsPage>(`/scans/${encodeURIComponent(id)}/events?since=${since}&limit=1500`),
  cancelScan: (id: string) =>
    request(`/scans/${encodeURIComponent(id)}/cancel`, { method: 'POST' }),
  findings: (id: string) =>
    request<{ findings: Finding[] }>(`/scans/${encodeURIComponent(id)}/findings`),
  deleteFindingFile: (scanId: string, findingId: string) =>
    request<{ deleted: boolean }>(
      `/scans/${encodeURIComponent(scanId)}/findings/${encodeURIComponent(findingId)}/delete`,
      { method: 'POST', body: { confirm: true } }),
  quarantineList: () => request<{ entries: QuarantineEntry[] }>('/quarantine'),
  quarantine: (findingId: string) =>
    request<QuarantineEntry>('/quarantine', { method: 'POST', body: { finding_id: findingId } }),
  quarantineRestore: (id: string, destination: 'original' | 'inbox') =>
    request<{ restored: boolean; restored_to: string }>(
      `/quarantine/${encodeURIComponent(id)}/restore`,
      { method: 'POST', body: { confirm: true, destination } }),
  quarantineDelete: (id: string) =>
    request(`/quarantine/${encodeURIComponent(id)}/delete`, { method: 'POST', body: { confirm: true } }),
  history: (limit = 100) => request<{ scans: ScanRecord[] }>(`/history?limit=${limit}`),
  deleteHistory: () =>
    request<{ deleted_scans: number }>('/history', { method: 'DELETE', body: { confirm: true } }),
  downloadReport: (scanId: string, format: 'json' | 'txt' | 'html') =>
    download(`/scans/${encodeURIComponent(scanId)}/report?format=${format}`,
             `usb-shield-report-${scanId}.${format}`),
  getConfig: () => request<Record<string, unknown>>('/config'),
  patchConfig: (patch: Record<string, unknown>) =>
    request<Record<string, unknown>>('/config', { method: 'PATCH', body: patch }),
  updateSignatures: () =>
    request<{ ok: boolean; output_tail: string; engine_version: string }>(
      '/engines/clamav/update', { method: 'POST' }),
  audit: (limit = 200) => request<{ events: AuditRow[] }>(`/audit?limit=${limit}`),
}
