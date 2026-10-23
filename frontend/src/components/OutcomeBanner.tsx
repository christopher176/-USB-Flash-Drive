import type { ScanRecord } from '../types'

// Outcome wording is deliberately precise: a "clean" message appears only
// when the engine finished with full coverage and no gaps.
export default function OutcomeBanner({ record, active }: { record: ScanRecord; active: boolean }) {
  if (active || record.status === 'queued' || record.status === 'scanning') {
    return (
      <div className="banner banner-scanning" role="status">
        <span className="pulse-dot" />
        <strong>Scanning {record.device_label}</strong> — {record.mode} mode.
        Keep the device connected.
      </div>
    )
  }
  if (record.status === 'cancelled') {
    return (
      <div className="banner banner-warn" role="alert">
        <strong>Scan cancelled.</strong> Results below cover only what was
        inspected before cancellation — this is <em>not</em> a clean bill of health.
      </div>
    )
  }
  if (record.status === 'failed') {
    const disconnected = record.error_code === 'DEVICE_DISCONNECTED'
    return (
      <div className="banner banner-failed" role="alert">
        <strong>Scan incomplete{disconnected ? ' — device disconnected' : ''}.</strong>{' '}
        {record.error_message || 'The scan stopped before finishing.'} Partial
        results only; the device has <em>not</em> been verified.
      </div>
    )
  }
  switch (record.outcome) {
    case 'threats_found': {
      const c = record.counters
      return (
        <div className="banner banner-danger" role="alert">
          <strong>Threats detected: {c.threats_found}.</strong>{' '}
          Review the findings below and quarantine them before using this device.
          {(c.files_unable > 0 || c.files_partial > 0 || c.dirs_failed > 0) && (
            <span className="banner-sub">
              Additionally, {c.files_unable + c.files_partial} file(s) could not be fully inspected.
            </span>
          )}
          {record.mode === 'quick' && <QuickNote />}
        </div>
      )
    }
    case 'no_threats_with_gaps':
      return (
        <div className="banner banner-warn" role="alert">
          <strong>No threats confirmed — but coverage had gaps.</strong>{' '}
          {record.counters.files_unable + record.counters.files_partial} file(s) and{' '}
          {record.counters.dirs_failed} folder(s) could not be fully inspected, so
          this device <em>cannot be certified clean</em>. See the “unable to scan”
          entries below. {record.mode === 'quick' && <QuickNote />}
        </div>
      )
    case 'clean':
      return (
        <div className="banner banner-clean" role="status">
          {record.mode === 'quick' ? (
            <>
              <strong>Quick scan complete — nothing detected in high-risk locations.</strong>{' '}
              Only {record.counters.files_scanned} high-risk file(s) were inspected;{' '}
              {record.counters.files_skipped} lower-risk file(s) were not read.
              Run a Full Deep Scan for complete coverage.
            </>
          ) : (
            <>
              <strong>Scan complete — no threats detected.</strong>{' '}
              All {record.counters.files_scanned} accessible file(s) in scope were
              fully inspected by {record.engines.length} engine(s). No scanner can
              prove a device is free of all possible malware; see the limitations
              in Security &amp; Privacy.
            </>
          )}
        </div>
      )
    case 'incomplete':
      return (
        <div className="banner banner-warn" role="alert">
          <strong>Scan incomplete{record.error_code ? ` (${record.error_code})` : ''}.</strong>{' '}
          {record.error_message || 'Stopped by a safety limit before completion.'}
        </div>
      )
    default:
      return (
        <div className="banner banner-info">
          <strong>Scan finished.</strong> Final outcome pending.
        </div>
      )
  }
}

function QuickNote() {
  return (
    <span className="banner-sub">
      Note: this was a quick scan — it does not provide the coverage of a full deep scan.
    </span>
  )
}
