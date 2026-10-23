import { useEffect, useRef } from 'react'
import type { ScanEvent } from '../types'
import { fmtClock } from '../format'

interface Props {
  events: ScanEvent[]
  active: boolean
}

export default function ActivityFeed({ events, active }: Props) {
  const boxRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    const el = boxRef.current
    if (el) el.scrollTop = el.scrollHeight
  }, [events.length])

  const notable = events.filter(e => e.type !== 'progress')
  return (
    <div className="card">
      <div className="card-title-row">
        <h2>Scan activity</h2>
        {active && <span className="live-badge"><span className="pulse-dot" /> live</span>}
      </div>
      <div className="activity-feed" ref={boxRef} aria-live="polite">
        {notable.length === 0 && (
          <div className="muted">Waiting for scan activity…</div>
        )}
        {notable.map(e => (
          <div key={e.seq} className={`feed-row feed-${e.level} feed-type-${e.type}`}>
            <span className="feed-time">{fmtClock(e.ts)}</span>
            <span className="feed-msg">{e.message}</span>
          </div>
        ))}
      </div>
    </div>
  )
}
