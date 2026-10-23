import { useMemo, useState } from 'react'
import { api } from '../api'
import type { Classification, Finding } from '../types'
import { fmtBytes } from '../format'
import FindingModal from './FindingModal'

interface Props {
  findings: Finding[]
  scanId: string
  deviceConnected: boolean
  onAction: () => Promise<void>
}

type Filter = 'all' | Classification

const FILTERS: Array<[Filter, string]> = [
  ['all', 'All'],
  ['malicious', 'Malicious'],
  ['suspicious', 'Suspicious'],
  ['potentially_unwanted', 'Potentially unwanted'],
  ['unable_to_scan', 'Unable to scan'],
]

const CLASS_LABEL: Record<string, string> = {
  malicious: 'malicious',
  suspicious: 'suspicious',
  potentially_unwanted: 'potentially unwanted',
  clean: 'clean',
  unable_to_scan: 'unable to scan',
}

export function ClassBadge({ c }: { c: Classification }) {
  return <span className={`badge badge-${c}`}>{CLASS_LABEL[c] || c}</span>
}

export function SeverityChip({ s }: { s: string }) {
  return <span className={`sev sev-${s}`}>{s}</span>
}

export default function FindingsTable({ findings, scanId, deviceConnected, onAction }: Props) {
  const [filter, setFilter] = useState<Filter>('all')
  const [selected, setSelected] = useState<Finding | null>(null)

  const counts = useMemo(() => {
    const m = new Map<Filter, number>()
    for (const f of findings) m.set(f.classification, (m.get(f.classification) || 0) + 1)
    m.set('all', findings.length)
    return m
  }, [findings])

  const threats = useMemo(
    () => findings.filter(f => ['malicious', 'suspicious', 'potentially_unwanted'].includes(f.classification)),
    [findings])

  const shown = filter === 'all' ? findings : findings.filter(f => f.classification === filter)

  return (
    <div className="card">
      <div className="card-title-row">
        <h2>
          Findings
          {threats.length > 0 && <span className="badge badge-malicious">{threats.length} threat(s)</span>}
        </h2>
        <div className="filter-row" role="tablist" aria-label="Filter findings">
          {FILTERS.map(([id, label]) => (
            <button key={id}
                    className={`chip ${filter === id ? 'chip-active' : ''}`}
                    onClick={() => setFilter(id)}>
              {label} {(counts.get(id) || 0) > 0 ? `(${counts.get(id)})` : ''}
            </button>
          ))}
        </div>
      </div>
      {shown.length === 0 ? (
        <div className="empty-state">
          <p>No {filter === 'all' ? '' : filter.replace(/_/g, ' ') + ' '}findings.</p>
        </div>
      ) : (
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>Classification</th>
                <th>Severity</th>
                <th>Path</th>
                <th>Detection</th>
                <th>Engine</th>
                <th>Size</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {shown.map(f => (
                <tr key={f.id}>
                  <td><ClassBadge c={f.classification} /></td>
                  <td><SeverityChip s={f.severity} /></td>
                  <td className="path-cell" title={f.container ? `inside ${f.container}` : f.path}>
                    {f.path}
                    {f.hidden && <span className="tag tag-hidden">hidden</span>}
                    {f.system_path && <span className="tag tag-system">system area</span>}
                    {f.is_test_detection && <span className="tag tag-test">test file</span>}
                    {f.quarantined && <span className="tag tag-quarantined">quarantined</span>}
                    {Boolean(f.extra?.deleted_from_device) && <span className="tag tag-deleted">deleted</span>}
                  </td>
                  <td>{f.detection_name || (f.status === 'partial' ? '—' : '—')}</td>
                  <td className="muted">{f.engine}</td>
                  <td className="muted">{fmtBytes(f.size)}</td>
                  <td>
                    <button className="btn btn-secondary btn-sm"
                            onClick={() => setSelected(f)}>
                      Review
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {selected && (
        <FindingModal
          finding={selected}
          scanId={scanId}
          deviceConnected={deviceConnected}
          onClose={() => setSelected(null)}
          onAction={async () => { setSelected(null); await onAction() }}
        />
      )}
    </div>
  )
}
