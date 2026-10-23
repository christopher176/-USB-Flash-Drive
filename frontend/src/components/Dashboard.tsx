import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { api } from '../api'
import type {
  AgentInfo, Device, Finding, ScanEvent, ScanMode, ScanRecord,
} from '../types'
import { fmtBytes } from '../format'
import ScanProgress from './ScanProgress'
import ActivityFeed from './ActivityFeed'
import FindingsTable from './FindingsTable'
import OutcomeBanner from './OutcomeBanner'

interface Props {
  info: AgentInfo | null
  onChanged: () => void
}

const MODE_INFO: Array<{ id: ScanMode; title: string; desc: string; warn?: string }> = [
  {
    id: 'quick', title: 'Quick Scan',
    desc: 'High-risk locations (device root, hidden & system folders) and high-risk file types (executables, scripts, shortcuts, archives, autorun files).',
    warn: 'Does not inspect every file — not a substitute for a Full Deep Scan.',
  },
  {
    id: 'full', title: 'Full Deep Scan',
    desc: 'Recursively inspects every accessible file, including hidden folders, system directories and nested archives.',
  },
  {
    id: 'custom', title: 'Custom Scan',
    desc: 'Inspect only the folders or files you choose on the device.',
  },
]

export default function Dashboard({ info, onChanged }: Props) {
  const [drives, setDrives] = useState<Device[]>([])
  const [drivesErr, setDrivesErr] = useState<string | null>(null)
  const [selected, setSelected] = useState<string>('')
  const [mode, setMode] = useState<ScanMode>('full')
  const [customPaths, setCustomPaths] = useState('')
  const [record, setRecord] = useState<ScanRecord | null>(null)
  const [events, setEvents] = useState<ScanEvent[]>([])
  const [percent, setPercent] = useState<number | null>(null)
  const [findings, setFindings] = useState<Finding[] | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [notice, setNotice] = useState<string | null>(null)
  const sinceRef = useRef(0)
  const pollingRef = useRef<number | null>(null)

  const loadDrives = useCallback(async () => {
    try {
      const res = await api.drives()
      setDrives(res.devices)
      setDrivesErr(null)
      setSelected(prev => (prev && res.devices.some(d => d.id === prev))
        ? prev : (res.devices[0]?.id ?? ''))
    } catch (err) {
      setDrivesErr(err instanceof Error ? err.message : 'Failed to list drives')
    }
  }, [])

  useEffect(() => {
    void loadDrives()
    const t = setInterval(loadDrives, 4000)
    return () => clearInterval(t)
  }, [loadDrives])

  const active = record && (record.status === 'queued' || record.status === 'scanning')

  const pollEvents = useCallback(async (scanId: string) => {
    try {
      const page = await api.scanEvents(scanId, sinceRef.current)
      sinceRef.current = page.next
      if (page.events.length) {
        setEvents(prev => [...prev, ...page.events].slice(-800))
        const last = page.events[page.events.length - 1]
        if (last.type === 'progress' || last.type === 'end') {
          setPercent(last.data.percent ?? null)
        }
      }
      setRecord(page.record)
      if (page.done) {
        if (pollingRef.current) { clearInterval(pollingRef.current); pollingRef.current = null }
        setPercent(100)
        const f = await api.findings(scanId)
        setFindings(f.findings)
        onChanged()
      }
    } catch { /* transient polling errors are ignored; next tick retries */ }
  }, [onChanged])

  const startScan = async () => {
    if (!selected) return
    setBusy(true); setError(null); setNotice(null)
    setEvents([]); setFindings(null); setRecord(null); setPercent(null)
    sinceRef.current = 0
    try {
      const paths = mode === 'custom'
        ? customPaths.split(/[\n,]+/).map(s => s.trim()).filter(Boolean)
        : []
      if (mode === 'custom' && !paths.length) {
        setError('Enter at least one folder or file path for a custom scan.')
        setBusy(false)
        return
      }
      const rec = await api.startScan({ device_id: selected, mode, custom_paths: paths })
      setRecord(rec)
      if (pollingRef.current) clearInterval(pollingRef.current)
      pollingRef.current = window.setInterval(() => void pollEvents(rec.id), 700)
      await pollEvents(rec.id)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not start scan')
    } finally {
      setBusy(false)
    }
  }

  const cancelScan = async () => {
    if (!record) return
    try {
      await api.cancelScan(record.id)
      setNotice('Cancellation requested — stopping safely…')
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Cancel failed')
    }
  }

  const eject = async (id: string) => {
    setError(null)
    try {
      const res = await api.eject(id)
      setNotice(res.message)
      void loadDrives()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Eject failed')
    }
  }

  const makeDemo = async () => {
    setBusy(true); setError(null)
    try {
      await api.createDemo()
      await loadDrives()
      setNotice('Synthetic demo device created (harmless test data, including the EICAR test string).')
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Demo creation failed')
    } finally { setBusy(false) }
  }

  const selectedDrive = useMemo(
    () => drives.find(d => d.id === selected) || null, [drives, selected])

  useEffect(() => () => {
    if (pollingRef.current) clearInterval(pollingRef.current)
  }, [])

  return (
    <div className="dashboard">
      <section className="grid-2">
        <div className="card">
          <div className="card-title-row">
            <h2>Connected devices</h2>
            <button className="btn btn-ghost btn-sm" onClick={() => void loadDrives()}>
              Refresh
            </button>
          </div>
          {drivesErr && <div className="banner banner-failed">{drivesErr}</div>}
          {drives.length === 0 && !drivesErr && (
            <div className="empty-state">
              <p>No removable USB device detected.</p>
              <p className="muted">
                System drives are never listed or scanned — only removable volumes.
                Insert a USB flash drive to begin.
              </p>
              {info?.dev_demo && (
                <button className="btn btn-secondary" onClick={makeDemo} disabled={busy}>
                  Create synthetic demo device (test data)
                </button>
              )}
            </div>
          )}
          <div className="drive-list">
            {drives.map(d => (
              <button
                key={d.id}
                className={`drive-card ${selected === d.id ? 'drive-selected' : ''} ${!d.available ? 'drive-offline' : ''}`}
                onClick={() => !active && setSelected(d.id)}
                disabled={!!active}
              >
                <div className="drive-head">
                  <span className={`drive-dot ${d.available ? 'dot-ok' : 'dot-bad'}`} />
                  <span className="drive-label">{d.label}</span>
                  {d.kind === 'demo' && <span className="pill pill-warn">demo</span>}
                </div>
                <div className="drive-meta">
                  <span>{d.mount_point}</span>
                  <span>{d.fs_type || 'filesystem'}</span>
                </div>
                <div className="drive-usage">
                  <div className="usage-bar">
                    <div className="usage-fill"
                         style={{ width: d.total_bytes ? `${Math.min(100, 100 * d.used_bytes / d.total_bytes)}%` : '0%' }} />
                  </div>
                  <span className="muted">
                    {fmtBytes(d.used_bytes)} used · {fmtBytes(d.free_bytes)} free of {fmtBytes(d.total_bytes)}
                  </span>
                </div>
              </button>
            ))}
          </div>
          {selectedDrive && !active && (
            <div className="drive-actions">
              <button className="btn btn-ghost btn-sm"
                      onClick={() => void eject(selectedDrive.id)}>
                Safely eject “{selectedDrive.label}”
              </button>
            </div>
          )}
        </div>

        <div className="card">
          <h2>Scan mode</h2>
          <div className="mode-list">
            {MODE_INFO.map(m => (
              <label key={m.id} className={`mode-card ${mode === m.id ? 'mode-active' : ''}`}>
                <input type="radio" name="scan-mode" value={m.id}
                       checked={mode === m.id}
                       disabled={!!active}
                       onChange={() => setMode(m.id)} />
                <div>
                  <div className="mode-title">{m.title}</div>
                  <div className="mode-desc">{m.desc}</div>
                  {m.warn && <div className="mode-warn">{m.warn}</div>}
                </div>
              </label>
            ))}
          </div>
          {mode === 'custom' && (
            <div className="custom-paths">
              <label htmlFor="custom-paths-input">
                Paths on the device (one per line, e.g. <code>Documents</code> or{' '}
                <code>Photos/trip</code>)
              </label>
              <textarea id="custom-paths-input" rows={3} value={customPaths}
                        disabled={!!active}
                        onChange={e => setCustomPaths(e.target.value)}
                        placeholder={'Documents\nDownloads/setup.exe'} />
            </div>
          )}
          <div className="scan-actions">
            {!active ? (
              <button className="btn btn-primary btn-lg" onClick={startScan}
                      disabled={busy || !selectedDrive || !selectedDrive.available}>
                {busy ? 'Starting…' : 'Scan USB'}
              </button>
            ) : (
              <button className="btn btn-danger" onClick={cancelScan}>
                Cancel scan
              </button>
            )}
            {selectedDrive && !selectedDrive.available && (
              <span className="muted">selected device is offline</span>
            )}
          </div>
          {error && <div className="banner banner-failed">{error}</div>}
          {notice && <div className="banner banner-info">{notice}</div>}
        </div>
      </section>

      {record && (
        <>
          <OutcomeBanner record={record} active={!!active} />
          <section className="grid-2">
            <ScanProgress record={record} percent={percent} active={!!active} />
            <ActivityFeed events={events} active={!!active} />
          </section>
          {findings && (
            <FindingsTable
              findings={findings}
              scanId={record.id}
              deviceConnected={drives.some(d => d.id === record.device_id && d.available)}
              onAction={async () => {
                const f = await api.findings(record.id)
                setFindings(f.findings)
                onChanged()
              }}
            />
          )}
        </>
      )}
      {record && !active && findings === null && (
        <div className="muted muted-center">Loading final results…</div>
      )}
    </div>
  )
}
