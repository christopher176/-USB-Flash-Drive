import { useCallback, useEffect, useState } from 'react'
import { api } from '../api'
import type { AgentInfo, AuditRow } from '../types'
import { fmtDateTime } from '../format'

export default function SecurityInfo({ info }: { info: AgentInfo | null }) {
  const [audit, setAudit] = useState<AuditRow[] | null>(null)

  const load = useCallback(async () => {
    try {
      const res = await api.audit(100)
      setAudit(res.events)
    } catch { setAudit([]) }
  }, [])

  useEffect(() => { void load() }, [load])

  return (
    <div className="security-info">
      <div className="card">
        <h2>What this system does — and does not do</h2>
        <ul className="truth-list">
          <li>Scanning runs <strong>locally on your computer</strong> by the local agent. File contents never leave this machine.</li>
          <li>Only <strong>removable devices you explicitly select</strong> are scanned. System drives are never touched.</li>
          <li>A “clean” result is shown only after a scan <strong>completed with full coverage and zero gaps</strong>. Partial coverage is always reported as such.</li>
          <li>Heuristic detections are labelled <strong>suspicious</strong>, never “confirmed malware” — confirmed detections require a signature-backed engine.</li>
          <li>Nothing is deleted automatically. Quarantine and delete require your explicit confirmation.</li>
          <li>ClamAV (when installed) supplies real malware signatures with verified automatic updates. Without it, coverage is the built-in test-signature and heuristic engines only.</li>
        </ul>
      </div>

      <div className="card">
        <h2>Privacy</h2>
        <ul className="truth-list">
          <li>Collected: scan metadata (paths, hashes, verdicts, counters), quarantine vault, audit log — all stored locally in <code>~/.usb-shield</code>.</li>
          <li>Not collected: file contents (quarantine excepted, and it stays local and encrypted), telemetry, analytics of any kind.</li>
          <li>“Delete all history” in History &amp; Reports erases scan records and saved reports.</li>
          <li>Full details: <code>docs/PRIVACY.md</code> in the project.</li>
        </ul>
      </div>

      <div className="card">
        <h2>Limitations</h2>
        <ul className="truth-list">
          <li>Encrypted archives and permission-protected files cannot be inspected and are reported under “unable to scan”.</li>
          <li>No antivirus can prove a device is free of all malware; zero-day and firmware-resident threats may not be detectable by file scanning.</li>
          <li>Quick Scan covers high-risk locations and types only.</li>
          <li>See <code>docs/LIMITATIONS.md</code> for the complete list.</li>
        </ul>
      </div>

      <div className="card">
        <div className="card-title-row">
          <h2>Security audit log</h2>
          <button className="btn btn-ghost btn-sm" onClick={() => void load()}>Refresh</button>
        </div>
        {audit === null ? (
          <div className="muted">Loading…</div>
        ) : audit.length === 0 ? (
          <div className="empty-state"><p>No audit events yet.</p></div>
        ) : (
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr><th>Time</th><th>Action</th><th>Actor</th><th>Detail</th><th>IP</th></tr>
              </thead>
              <tbody>
                {audit.map(a => (
                  <tr key={a.id}>
                    <td className="muted">{fmtDateTime(a.ts)}</td>
                    <td><code>{a.action}</code></td>
                    <td className="muted">{a.actor}</td>
                    <td className="muted path-cell">{a.detail}</td>
                    <td className="muted">{a.ip}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  )
}
