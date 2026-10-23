import { useState } from 'react'
import { api, ApiError, setPairing, setToken } from '../api'
import { ShieldLogo } from './Header'

export default function ConnectGate({ onConnected }: { onConnected: () => void }) {
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [manual, setManual] = useState('')
  const [showManual, setShowManual] = useState(false)

  const pair = async () => {
    setBusy(true); setError(null)
    try {
      const res = await api.pair()
      setPairing(res)
      onConnected()
    } catch (err) {
      if (err instanceof ApiError && err.status === 0) {
        setError('Cannot reach the local agent. Start it with: python -m usb_shield')
      } else if (err instanceof ApiError && err.status === 429) {
        setError('Too many pairing attempts. Wait a minute and try again.')
      } else if (err instanceof ApiError && err.status === 403) {
        setError('Pairing is only allowed from the same machine the agent runs on.')
      } else {
        setError(err instanceof Error ? err.message : 'Pairing failed')
      }
    } finally {
      setBusy(false)
    }
  }

  const connectManual = async () => {
    setBusy(true); setError(null)
    try {
      const t = manual.trim()
      setToken(t)
      await api.info()
      onConnected()
    } catch (err) {
      setToken('')
      setError(err instanceof ApiError && err.status === 401
        ? 'That token was rejected by the agent.'
        : 'Could not connect with that token.')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="connect-gate">
      <div className="connect-card">
        <ShieldLogo size={46} />
        <h1>USB Shield</h1>
        <p className="muted">
          Pair this dashboard with the local scanning agent running on your
          computer. Pairing proves you are sitting at this machine — websites
          cannot do it for you.
        </p>
        {error && <div className="banner banner-failed">{error}</div>}
        <button className="btn btn-primary btn-lg" onClick={pair} disabled={busy}>
          {busy ? 'Pairing…' : 'Pair with local agent'}
        </button>
        <button className="btn btn-ghost" onClick={() => setShowManual(s => !s)}>
          {showManual ? 'Hide manual token entry' : 'Enter token manually'}
        </button>
        {showManual && (
          <div className="manual-token">
            <label htmlFor="token-input">Agent admin token (advanced)</label>
            <input
              id="token-input"
              type="password"
              value={manual}
              onChange={e => setManual(e.target.value)}
              placeholder="Paste ~/.usb-shield/agent_token (admin credential)"
              autoComplete="off"
              spellCheck={false}
            />
            <button className="btn btn-secondary" onClick={connectManual}
                    disabled={busy || manual.trim().length < 16}>
              Connect
            </button>
          </div>
        )}
        <p className="fine-print">
          Pairing issues short-lived access tokens that refresh automatically.
          Everything stays in this browser’s localStorage and is sent only to
          your local agent over this same origin — never to any remote server.
        </p>
      </div>
    </div>
  )
}
