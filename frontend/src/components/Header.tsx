import type { AgentInfo } from '../types'

export function ShieldLogo({ size = 28 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 64 64" fill="none"
         aria-hidden="true">
      <defs>
        <linearGradient id="shield-g" x1="0" y1="0" x2="1" y2="1">
          <stop offset="0%" stopColor="#38bdf8" />
          <stop offset="100%" stopColor="#2563eb" />
        </linearGradient>
      </defs>
      <path d="M32 3 55 12v17c0 15.5-9.8 26.4-23 32C18.8 55.4 9 44.5 9 29V12L32 3z"
            fill="url(#shield-g)" opacity="0.95" />
      <path d="M22 31.5 29 38l13-14" stroke="#0a1120" strokeWidth="5"
            strokeLinecap="round" strokeLinejoin="round" fill="none" />
    </svg>
  )
}

interface Props {
  info: AgentInfo | null
  agentDown: boolean
  tab: string
  onTab: (t: 'dashboard' | 'quarantine' | 'history' | 'settings' | 'security') => void
  onDisconnect: () => void
}

const TABS: Array<[string, string]> = [
  ['dashboard', 'Scan'],
  ['quarantine', 'Quarantine'],
  ['history', 'History & Reports'],
  ['settings', 'Settings'],
  ['security', 'Security & Privacy'],
]

export default function Header({ info, agentDown, tab, onTab, onDisconnect }: Props) {
  const clam = info?.engines.find(e => e.name === 'clamav')
  return (
    <header className="app-header">
      <div className="header-inner">
        <div className="brand">
          <ShieldLogo />
          <div>
            <div className="brand-name">USB Shield</div>
            <div className="brand-sub">removable-media threat scanner</div>
          </div>
        </div>
        <nav className="tabs" aria-label="Main navigation">
          {TABS.map(([id, label]) => (
            <button key={id}
                    className={`tab ${tab === id ? 'tab-active' : ''}`}
                    onClick={() => onTab(id as never)}>
              {label}
            </button>
          ))}
        </nav>
        <div className="header-status">
          {info && (
            <span className={`pill ${clam?.available ? 'pill-ok' : 'pill-warn'}`}
                  title={clam?.detail || ''}>
              {clam?.available
                ? `ClamAV ${clam.version.split('/')[0].replace('ClamAV ', '')}`
                : 'ClamAV not detected'}
            </span>
          )}
          <span className={`pill ${agentDown ? 'pill-bad' : 'pill-ok'}`}>
            {agentDown ? 'agent offline' : 'agent connected'}
          </span>
          <button className="btn btn-ghost btn-sm" onClick={onDisconnect}
                  title="Forget the agent token in this browser">
            Disconnect
          </button>
        </div>
      </div>
    </header>
  )
}
