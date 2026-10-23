import { useCallback, useEffect, useState } from 'react'
import { api } from '../api'
import type { QuarantineEntry } from '../types'
import { fmtBytes, fmtDateTime } from '../format'
import { ClassBadge, SeverityChip } from './FindingsTable'

export default function QuarantinePanel() {
  const [entries, setEntries] = useState<QuarantineEntry[] | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [notice, setNotice] = useState<string | null>(null)
  const [confirm, setConfirm] = useState<{ id: string; kind: 'restore' | 'delete' } | null>(null)
  const [dest, setDest] = useState<'original' | 'inbox'>('original')
  const [busy, setBusy] = useState(false)

  const load = useCallback(async () => {
    try {
      const res = await api.quarantineList()
      setEntries(res.entries)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not load vault')
    }
  }, [])

  useEffect(() => { void load() }, [load])

  const act = async () => {
    if (!confirm) return
    setBusy(true); setError(null); setNotice(null)
    try {
      if (confirm.kind === 'restore') {
        const r = await api.quarantineRestore(confirm.id, dest)
        setNotice(`Restored to ${r.restored_to}. Rescan recommended.`)
      } else {
        await api.quarantineDelete(confirm.id)
        setNotice('Quarantined copy permanently destroyed.')
      }
      setConfirm(null)
      await load()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Action failed')
      setConfirm(null)
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="card">
      <div className="card-title-row">
        <h2>Quarantine vault</h2>
        <button className="btn btn-ghost btn-sm" onClick={() => void load()}>Refresh</button>
      </div>
      <p className="muted">
        Quarantined files are encrypted with AES-256-GCM, stored outside any USB
        device with owner-only permissions, and cannot execute. Every action is
        audit-logged.
      </p>
      {error && <div className="banner banner-failed">{error}</div>}
      {notice && <div className="banner banner-info">{notice}</div>}
      {entries === null ? (
        <div className="muted">Loading…</div>
      ) : entries.length === 0 ? (
        <div className="empty-state"><p>The vault is empty.</p></div>
      ) : (
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>Status</th><th>Classification</th><th>Severity</th>
                <th>Original path</th><th>Detection</th><th>Size</th>
                <th>Quarantined</th><th></th>
              </tr>
            </thead>
            <tbody>
              {entries.map(e => (
                <tr key={e.id}>
                  <td><span className={`tag tag-${e.status}`}>{e.status}</span></td>
                  <td><ClassBadge c={e.classification} /></td>
                  <td><SeverityChip s={e.severity} /></td>
                  <td className="path-cell">
                    {e.original_path}
                    <div className="muted">{e.device_label}</div>
                  </td>
                  <td>{e.detection_name || '—'}</td>
                  <td className="muted">{fmtBytes(e.size)}</td>
                  <td className="muted">{fmtDateTime(e.created_at)}</td>
                  <td className="row-actions">
                    {e.status === 'quarantined' && (
                      <>
                        <button className="btn btn-secondary btn-sm"
                                onClick={() => { setDest('original'); setConfirm({ id: e.id, kind: 'restore' }) }}>
                          Restore…
                        </button>
                        <button className="btn btn-outline-danger btn-sm"
                                onClick={() => setConfirm({ id: e.id, kind: 'delete' })}>
                          Destroy…
                        </button>
                      </>
                    )}
                    {e.restored_to && <span className="muted">{e.restored_to}</span>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {confirm && (
        <div className="modal-backdrop" role="dialog" aria-modal="true"
             onClick={() => setConfirm(null)}>
          <div className="modal" onClick={ev => ev.stopPropagation()}>
            <div className="modal-head">
              <h3>{confirm.kind === 'restore' ? 'Restore from quarantine' : 'Destroy quarantined copy'}</h3>
              <button className="btn btn-ghost btn-sm" onClick={() => setConfirm(null)}>✕</button>
            </div>
            <div className="modal-body">
              {confirm.kind === 'restore' ? (
                <>
                  <p>
                    Restoring returns the file to its original device location
                    (or to the agent’s restore inbox if the device is absent).
                    Only restore files you have determined to be safe — this
                    reverses your protection.
                  </p>
                  <label className="radio-row">
                    <input type="radio" checked={dest === 'original'}
                           onChange={() => setDest('original')} />
                    Original location (device must be connected)
                  </label>
                  <label className="radio-row">
                    <input type="radio" checked={dest === 'inbox'}
                           onChange={() => setDest('inbox')} />
                    Restore inbox on this computer
                  </label>
                </>
              ) : (
                <p>
                  <strong>Permanently destroy</strong> the encrypted quarantined
                  copy. This cannot be undone.
                </p>
              )}
              {error && <div className="banner banner-failed">{error}</div>}
            </div>
            <div className="modal-actions">
              <button className="btn btn-secondary" onClick={() => setConfirm(null)} disabled={busy}>
                Cancel
              </button>
              <button className={`btn ${confirm.kind === 'delete' ? 'btn-danger' : 'btn-primary'}`}
                      onClick={act} disabled={busy}>
                {busy ? 'Working…' : confirm.kind === 'restore' ? 'Confirm restore' : 'Confirm destroy'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
