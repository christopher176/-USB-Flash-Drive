import { useCallback, useEffect, useState } from 'react'
import { api } from '../api'
import type { AgentInfo } from '../types'

interface Props {
  info: AgentInfo | null
  onChanged: () => void
}

const BOOL_OPTIONS: Array<[string, string, string]> = [
  ['heuristics_enabled', 'Heuristic engine',
   'Detect disguise, autorun abuse, suspicious scripts and atypical executable placement.'],
  ['test_signature_engine_enabled', 'EICAR test-signature engine',
   'Detects the harmless industry-standard EICAR test file; validates the pipeline end to end.'],
  ['archive_scan_enabled', 'Inspect archives',
   'Scan inside zip/tar archives with bomb and nesting limits.'],
]

const NUM_OPTIONS: Array<[string, string, string, number, number, number]> = [
  // key, label, help, min, max, scale-divisor (unit shown)
  ['max_depth', 'Traversal depth limit', 'Maximum nested folder depth to descend into.', 1, 128, 1],
  ['max_file_bytes', 'Max file size inspected (MB)', 'Larger files are header-inspected and reported as partially scanned.', 1, 4096, 1024 * 1024],
  ['scan_time_limit_seconds', 'Scan time limit (minutes)', 'A scan exceeding this stops and is reported as incomplete.', 1, 720, 60],
  ['archive_max_depth', 'Archive nesting limit', 'How deep archives inside archives are opened.', 0, 8, 1],
  ['archive_max_member_bytes', 'Max archive member size (MB)', 'Single compressed member size limit.', 1, 1024, 1024 * 1024],
  ['archive_max_total_bytes', 'Max total decompressed (MB)', 'Total decompressed bytes per archive (bomb protection).', 1, 8192, 1024 * 1024],
  ['archive_max_ratio', 'Compression ratio limit', 'Members beyond this ratio are flagged as possible bombs.', 2, 10000, 1],
  ['archive_time_budget_seconds', 'Archive time budget (s)', 'Wall-clock limit for one archive.', 1, 600, 1],
]

export default function SettingsPanel({ info, onChanged }: Props) {
  const [config, setConfig] = useState<Record<string, unknown> | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [notice, setNotice] = useState<string | null>(null)
  const [updating, setUpdating] = useState(false)
  const [updateOut, setUpdateOut] = useState<string | null>(null)

  const load = useCallback(async () => {
    try {
      setConfig(await api.getConfig())
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not load configuration')
    }
  }, [])

  useEffect(() => { void load() }, [load])

  const patch = async (body: Record<string, unknown>) => {
    setError(null); setNotice(null)
    try {
      const next = await api.patchConfig(body)
      setConfig(next)
      setNotice('Saved. New scans will use the updated settings.')
      onChanged()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Save failed')
      void load()
    }
  }

  const clam = info?.engines.find(e => e.name === 'clamav')

  const updateSignatures = async () => {
    setUpdating(true); setError(null); setUpdateOut(null)
    try {
      const r = await api.updateSignatures()
      setUpdateOut(r.output_tail.split('\n').filter(Boolean).slice(-3).join('\n'))
      onChanged()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Update failed')
    } finally {
      setUpdating(false)
    }
  }

  return (
    <div className="settings">
      <div className="card">
        <h2>Detection engines</h2>
        <div className="engine-list">
          {info?.engines.map(e => (
            <div key={e.name} className="engine-row">
              <span className={`pill ${e.available ? 'pill-ok' : 'pill-warn'}`}>
                {e.available ? 'active' : 'unavailable'}
              </span>
              <div className="engine-info">
                <div className="engine-name">{e.name}
                  <span className="muted"> · {e.version}</span>
                </div>
                <div className="muted">{e.description}</div>
                {!e.available && e.detail && <div className="muted">{e.detail}</div>}
              </div>
            </div>
          ))}
        </div>
        {clam && !clam.available && (
          <p className="muted">
            ClamAV provides real malware signature coverage. Install the
            <code> clamav-daemon </code> package on this machine and the agent will
            use it automatically, including verified signature updates.
          </p>
        )}
        <div className="row-actions">
          <button className="btn btn-secondary"
                  disabled={!clam?.available || updating}
                  title={clam?.available ? 'Run freshclam to update the signature database'
                                          : 'ClamAV daemon not detected'}
                  onClick={updateSignatures}>
            {updating ? 'Updating…' : 'Update ClamAV signatures'}
          </button>
        </div>
        {updateOut && <pre className="output-box">{updateOut}</pre>}
      </div>

      <div className="card">
        <h2>Scan behaviour</h2>
        {error && <div className="banner banner-failed">{error}</div>}
        {notice && <div className="banner banner-info">{notice}</div>}
        {!config ? (
          <div className="muted">Loading…</div>
        ) : (
          <>
            <div className="settings-grid">
              {BOOL_OPTIONS.map(([key, label, help]) => (
                <label key={key} className="setting-row">
                  <input
                    type="checkbox"
                    checked={Boolean(config[key])}
                    onChange={e => void patch({ [key]: e.target.checked })}
                  />
                  <div>
                    <div>{label}</div>
                    <div className="muted">{help}</div>
                  </div>
                </label>
              ))}
            </div>
            <div className="settings-grid">
              {NUM_OPTIONS.map(([key, label, help, min, max, div]) => {
                const raw = Number(config[key] ?? 0)
                const shown = Math.round(raw / div)
                return (
                  <label key={key} className="setting-row setting-number">
                    <div>
                      <div>{label}</div>
                      <div className="muted">{help}</div>
                    </div>
                    <input
                      type="number" min={min} max={max} value={shown}
                      onChange={e => {
                        const v = Number(e.target.value)
                        if (Number.isFinite(v) && v >= min && v <= max) {
                          void patch({ [key]: Math.round(v * div) })
                        }
                      }}
                    />
                  </label>
                )
              })}
            </div>
          </>
        )}
      </div>

      <div className="card">
        <h2>Connection</h2>
        <table className="kv-table">
          <tbody>
            <tr><th>Agent</th><td>{info ? `${info.name} v${info.version}` : 'offline'}</td></tr>
            <tr><th>Loopback-only binding</th>
                <td>{info?.loopback_bind ? 'yes (recommended)' : 'NO — check configuration'}</td></tr>
            <tr><th>User accounts</th><td>{info?.accounts_enabled ? 'enabled (Argon2id + TOTP)' : 'disabled'}</td></tr>
            <tr><th>Demo endpoint</th><td>{info?.dev_demo ? 'enabled (development only)' : 'disabled'}</td></tr>
          </tbody>
        </table>
      </div>
    </div>
  )
}
