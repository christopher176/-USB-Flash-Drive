import { useState } from 'react'
import { api } from '../api'
import type { Finding } from '../types'
import { fmtBytes } from '../format'
import { ClassBadge, SeverityChip } from './FindingsTable'

interface Props {
  finding: Finding
  scanId: string
  deviceConnected: boolean
  onClose: () => void
  onAction: () => Promise<void>
}

type Pending = null | 'quarantine' | 'delete'

export default function FindingModal({ finding, scanId, deviceConnected, onClose, onAction }: Props) {
  const [pending, setPending] = useState<Pending>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const f = finding
  const isThreat = ['malicious', 'suspicious', 'potentially_unwanted'].includes(f.classification)
  const inArchive = f.container !== null || f.path.includes('::')
  const resolved = f.quarantined || Boolean(f.extra?.deleted_from_device)
  const canAct = isThreat && !inArchive && !resolved && deviceConnected

  const act = async () => {
    setBusy(true); setError(null)
    try {
      if (pending === 'quarantine') await api.quarantine(f.id)
      if (pending === 'delete') await api.deleteFindingFile(scanId, f.id)
      await onAction()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Action failed')
      setBusy(false)
      setPending(null)
    }
  }

  const rows: Array<[string, React.ReactNode]> = [
    ['Path', <code key="p">{f.path}</code>],
    ...(f.container ? [['Contained in', <code key="c">{f.container}</code>] as [string, React.ReactNode]] : []),
    ['Classification', <ClassBadge key="cl" c={f.classification} />],
    ['Severity', <SeverityChip key="sv" s={f.severity} />],
    ['Detection', f.detection_name || '—'],
    ['Detection method', f.method || '—'],
    ['Engine', f.engine || '—'],
    ...(f.is_test_detection
      ? [['Test detection', 'yes — this is the harmless, industry-standard EICAR antivirus test file'] as [string, React.ReactNode]]
      : []),
    ['Status', f.status + (f.reason ? ` — ${f.reason}` : '')],
    ['Size', fmtBytes(f.size)],
    ['SHA-256', f.sha256 ? <code key="h">{f.sha256}</code> : '—'],
    ['Attributes', [
      f.hidden ? 'hidden' : null,
      f.system_path ? 'system area' : null,
    ].filter(Boolean).join(', ') || '—'],
    ['Recommended action', f.recommended_action],
  ]

  return (
    <div className="modal-backdrop" role="dialog" aria-modal="true"
         onClick={onClose}>
      <div className="modal" onClick={e => e.stopPropagation()}>
        <div className="modal-head">
          <h3>Review finding</h3>
          <button className="btn btn-ghost btn-sm" onClick={onClose}>✕</button>
        </div>
        <div className="modal-body">
          <table className="kv-table">
            <tbody>
              {rows.map(([k, v]) => (
                <tr key={k}><th>{k}</th><td>{v}</td></tr>
              ))}
            </tbody>
          </table>
          {f.classification === 'suspicious' && (
            <p className="muted">
              Heuristic detections describe suspicious characteristics, not
              confirmed infections. Quarantine keeps the file encrypted outside
              the device while you investigate.
            </p>
          )}
          {inArchive && isThreat && (
            <p className="muted">
              This entry lives inside an archive. Items inside archives cannot be
              quarantined or removed individually — quarantine or delete the
              archive {f.container ? <code>{f.container}</code> : ''} itself.
            </p>
          )}
          {!deviceConnected && (
            <p className="muted">The device is not currently connected; actions are disabled.</p>
          )}
          {error && <div className="banner banner-failed">{error}</div>}
        </div>
        <div className="modal-actions">
          {pending === null && (
            <>
              {canAct && (
                <>
                  <button className="btn btn-danger" onClick={() => setPending('quarantine')}>
                    Quarantine
                  </button>
                  <button className="btn btn-outline-danger" onClick={() => setPending('delete')}>
                    Delete from device
                  </button>
                </>
              )}
              <button className="btn btn-secondary" onClick={onClose}>Close</button>
            </>
          )}
          {pending !== null && (
            <div className="confirm-strip">
              {pending === 'quarantine' ? (
                <span>
                  Quarantine encrypts the file into the local vault and removes
                  it from the device. It can be restored later.
                </span>
              ) : (
                <span>
                  <strong>Permanent deletion.</strong> The file is removed from
                  the USB device immediately and cannot be recovered. Quarantine
                  is the safer option.
                </span>
              )}
              <div className="confirm-buttons">
                <button className="btn btn-secondary" onClick={() => setPending(null)} disabled={busy}>
                  Back
                </button>
                <button className="btn btn-danger" onClick={act} disabled={busy}>
                  {busy ? 'Working…' : pending === 'quarantine' ? 'Confirm quarantine' : 'Confirm permanent delete'}
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
