import { useCallback, useEffect, useState } from 'react'
import { api, ApiError, getToken, setToken } from './api'
import type { AgentInfo } from './types'
import ConnectGate from './components/ConnectGate'
import Header from './components/Header'
import Dashboard from './components/Dashboard'
import QuarantinePanel from './components/QuarantinePanel'
import HistoryPanel from './components/HistoryPanel'
import SettingsPanel from './components/SettingsPanel'
import SecurityInfo from './components/SecurityInfo'

type Tab = 'dashboard' | 'quarantine' | 'history' | 'settings' | 'security'

export default function App() {
  const [info, setInfo] = useState<AgentInfo | null>(null)
  const [connectError, setConnectError] = useState<string | null>(null)
  const [authed, setAuthed] = useState<boolean>(!!getToken())
  const [tab, setTab] = useState<Tab>('dashboard')
  const [reloadKey, setReloadKey] = useState(0)

  const refreshInfo = useCallback(async () => {
    try {
      const i = await api.info()
      setInfo(i)
      setConnectError(null)
      return true
    } catch (err) {
      if (err instanceof ApiError && (err.status === 401 || err.status === 403)) {
        setAuthed(false)
        return false
      }
      setConnectError(err instanceof Error ? err.message : String(err))
      setInfo(null)
      return false
    }
  }, [])

  useEffect(() => {
    if (!authed) { setInfo(null); return }
    let alive = true
    refreshInfo()
    const t = setInterval(() => { if (alive) void refreshInfo() }, 5000)
    return () => { alive = false; clearInterval(t) }
  }, [authed, reloadKey, refreshInfo])

  const onConnected = () => { setAuthed(true); setReloadKey(k => k + 1) }
  const onDisconnect = () => { setToken(''); setAuthed(false) }

  if (!authed) return <ConnectGate onConnected={onConnected} />

  const agentDown = !info && !!connectError

  return (
    <div className="app-shell">
      <Header
        info={info}
        agentDown={agentDown}
        tab={tab}
        onTab={setTab}
        onDisconnect={onDisconnect}
      />
      {agentDown && (
        <div className="banner banner-failed" role="alert">
          <strong>Agent unreachable.</strong> {connectError} The dashboard will
          reconnect automatically when the local agent is back.
        </div>
      )}
      <main className="app-main">
        {tab === 'dashboard' && (
          <Dashboard info={info} onChanged={() => setReloadKey(k => k + 1)} />
        )}
        {tab === 'quarantine' && <QuarantinePanel />}
        {tab === 'history' && <HistoryPanel />}
        {tab === 'settings' && <SettingsPanel info={info} onChanged={() => setReloadKey(k => k + 1)} />}
        {tab === 'security' && <SecurityInfo info={info} />}
      </main>
      <footer className="app-footer">
        <span>USB Shield {info?.version || ''} · local-first scanning · your files never leave this machine</span>
        <span className="muted">
          A scan result of “clean” means every in-scope file was fully inspected — never an estimate.
        </span>
      </footer>
    </div>
  )
}
