import type { ScanRecord } from '../types'
import { fmtBytes, fmtDuration } from '../format'

interface Props {
  record: ScanRecord
  percent: number | null
  active: boolean
}

export default function ScanProgress({ record, percent, active }: Props) {
  const c = record.counters
  const pct = active
    ? (percent ?? (c.estimate_complete && c.estimate_total
        ? Math.min(99, (100 * c.entries_seen) / Math.max(1, c.estimate_total))
        : null))
    : 100
  const stats: Array<[string, string | number]> = [
    ['Files scanned', c.files_scanned],
    ['Folders inspected', c.dirs_scanned],
    ['Threats detected', c.threats_found],
    ['Files skipped', c.files_skipped + c.symlinks_skipped + c.special_skipped],
    ['Partial / unable', c.files_partial + c.files_unable],
    ['Archives inspected', c.archives_inspected],
    ['Data read', fmtBytes(c.bytes_scanned)],
    ['Elapsed', fmtDuration(record.duration_seconds)],
  ]
  return (
    <div className="card">
      <div className="card-title-row">
        <h2>Progress</h2>
        <span className={`pill ${active ? 'pill-info' : 'pill-ok'}`}>
          {active ? 'running' : 'finished'}
        </span>
      </div>
      <div className="progress-wrap">
        <div className="progress-bar" role="progressbar"
             aria-valuenow={pct ?? undefined} aria-valuemin={0} aria-valuemax={100}>
          <div
            className={`progress-fill ${active ? 'progress-animated' : ''} ${pct == null ? 'progress-indeterminate' : ''}`}
            style={{ width: pct == null ? '35%' : `${pct}%` }}
          />
        </div>
        <span className="progress-label">
          {pct == null ? 'estimating…' : `${pct.toFixed(1)}%`}
        </span>
      </div>
      {!c.estimate_complete && active && (
        <p className="muted">Very large device — total size still being established.</p>
      )}
      <div className="stat-grid">
        {stats.map(([label, value]) => (
          <div key={label} className="stat">
            <div className={`stat-value ${label === 'Threats detected' && Number(value) > 0 ? 'stat-danger' : ''}`}>
              {value}
            </div>
            <div className="stat-label">{label}</div>
          </div>
        ))}
      </div>
    </div>
  )
}
