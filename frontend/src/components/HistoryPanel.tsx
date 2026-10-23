import { useCallback, useEffect, useState } from 'react'
import { api } from '../api'
import type { ScanRecord } from '../types'
import { fmtBytes, fmtDateTime, fmtDuration } from '../format'

const OUTCOME_CHIP: Record<string, [string, string]> = {
  clean: ['pill-ok', 'clean'],
  threats_found: ['pill-bad', 'threats found'],
  no_threats_with_gaps: ['pill-warn', 'no threats · gaps'],
  incomplete: ['pill-warn', 'incomplete'],
  pending: ['pill-info', 'pending'],
}

function HistoryRow({ s }: { s: ScanRecord }) {
  const [chip, label] = OUTCOME_CHIP[s.outcome] || ['pill-info', s.outcome]
  const [dlErr, setDlErr] = useState<string | null>(null)
  const download = async (format: 'json' | 'txt' | 'html') => {
    setDlErr(null)
    try {
      await api.downloadReport(s.id, format)
    } catch (err) {
      setDlErr(err instanceof Error ? err.message : 'download failed')
    }
  }
  return (
    <tr>
      <td className="muted">{fmtDateTime(s.finished_at || s.created_at)}</td>
      <td>{s.device_label}</td>
      <td className="muted">{s.mode}</td>
      <td><span className={`pill ${chip}`}>{label}</span></td>
      <td className="muted">{s.status}{s.error_code ? ` · ${s.error_code}` : ''}</td>
      <td className="muted">
        {s.counters.files_scanned} files · {s.counters.threats_found} threats
        {s.counters.files_unable + s.counters.files_partial > 0 &&
          ` · ${s.counters.files_unable + s.counters.files_partial} gaps`}
      </td>
      <td className="muted">{fmtDuration(s.duration_seconds)}</td>
      <td className="row-actions">
        <button className="btn btn-ghost btn-sm" onClick={() => void download('html')}>HTML</button>
        <button className="btn btn-ghost btn-sm" onClick={() => void download('txt')}>TXT</button>
        <button className="btn btn-ghost btn-sm" onClick={() => void download('json')}>JSON</button>
        {dlErr && <span className="muted">{dlErr}</span>}
      </td>
    </tr>
  )
}

export default function HistoryPanel() {
  const [scans, setScans] = useState<ScanRecord[] | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [confirming, setConfirming] = useState(false)
  const [busy, setBusy] = useState(false)

  const load = useCallback(async () => {
    try {
      const res = await api.history()
      // newest first
      setScans([...res.scans].sort((a, b) => b.created_at - a.created_at))
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not load history')
    }
  }, [])

  useEffect(() => { void load() }, [load])

  const wipe = async () => {
    setBusy(true)
    try {
      await api.deleteHistory()
      setConfirming(false)
      await load()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Delete failed')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="card">
      <div className="card-title-row">
        <h2>Scan history &amp; reports</h2>
        <div className="row-actions">
          <button className="btn btn-ghost btn-sm" onClick={() => void load()}>Refresh</button>
          <button className="btn btn-outline-danger btn-sm" onClick={() => setConfirming(true)}>
            Delete all history…
          </button>
        </div>
      </div>
      <p className="muted">
        History is stored only on this computer. Reports contain file paths and
        hashes — treat them as sensitive.
      </p>
      {error && <div className="banner banner-failed">{error}</div>}
      {scans === null ? (
        <div className="muted">Loading…</div>
      ) : scans.length === 0 ? (
        <div className="empty-state"><p>No scans recorded yet.</p></div>
      ) : (
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>Finished</th><th>Device</th><th>Mode</th><th>Outcome</th>
                <th>Engine status</th><th>Coverage</th><th>Duration</th><th>Report</th>
              </tr>
            </thead>
            <tbody>
              {scans.map(s => <HistoryRow key={s.id} s={s} />)}
            </tbody>
          </table>
        </div>
      )}
      {confirming && (
        <div className="modal-backdrop" role="dialog" aria-modal="true"
             onClick={() => setConfirming(false)}>
          <div className="modal" onClick={e => e.stopPropagation()}>
            <div className="modal-head">
              <h3>Delete all scan history</h3>
              <button className="btn btn-ghost btn-sm" onClick={() => setConfirming(false)}>✕</button>
            </div>
            <div className="modal-body">
              <p>
                This erases every stored scan record, finding and saved report
                from this computer ({scans?.length ?? 0} scan(s)). Quarantined
                files are <em>not</em> affected. This cannot be undone.
              </p>
            </div>
            <div className="modal-actions">
              <button className="btn btn-secondary" onClick={() => setConfirming(false)} disabled={busy}>
                Cancel
              </button>
              <button className="btn btn-danger" onClick={wipe} disabled={busy}>
                {busy ? 'Deleting…' : 'Delete everything'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
