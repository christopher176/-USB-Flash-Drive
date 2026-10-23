// Type mirrors of the agent's API models.

export type Classification =
  | 'malicious' | 'suspicious' | 'potentially_unwanted' | 'clean' | 'unable_to_scan'
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info' | 'none'
export type ScanMode = 'quick' | 'full' | 'custom'
export type ScanStatus = 'queued' | 'scanning' | 'completed' | 'failed' | 'cancelled'
export type ScanOutcome =
  | 'pending' | 'clean' | 'threats_found' | 'no_threats_with_gaps' | 'incomplete'

export interface Device {
  id: string
  label: string
  mount_point: string
  fs_type: string
  total_bytes: number
  used_bytes: number
  free_bytes: number
  kind: 'removable' | 'demo'
  available: boolean
  detail: string
}

export interface ScanCounters {
  entries_seen: number
  dirs_scanned: number
  dirs_failed: number
  files_scanned: number
  files_partial: number
  files_skipped: number
  files_unable: number
  symlinks_skipped: number
  special_skipped: number
  bytes_scanned: number
  threats_found: number
  archives_inspected: number
  estimate_total: number | null
  estimate_complete: boolean
}

export interface ScanRecord {
  id: string
  device_id: string
  device_label: string
  device_mount: string
  mode: ScanMode
  custom_paths: string[]
  status: ScanStatus
  outcome: ScanOutcome
  counters: ScanCounters
  created_at: number
  started_at: number | null
  finished_at: number | null
  duration_seconds: number | null
  error_code: string | null
  error_message: string | null
  engines: string[]
  engine_versions: Record<string, string>
  config_snapshot: Record<string, unknown>
  agent_version: string
}

export interface ScanEvent {
  seq: number
  ts: number
  type: string
  level: string
  message: string
  path: string | null
  data: Record<string, unknown> & { percent?: number | null }
}

export interface ScanEventsPage {
  events: ScanEvent[]
  next: number
  done: boolean
  dropped?: number
  record: ScanRecord
}

export interface Finding {
  id: string
  scan_id: string
  device_id: string
  path: string
  container: string | null
  classification: Classification
  severity: Severity
  detection_name: string
  engine: string
  method: string
  status: string
  reason: string | null
  size: number
  sha256: string | null
  hidden: boolean
  system_path: boolean
  recommended_action: string
  is_test_detection: boolean
  quarantined: boolean
  extra: Record<string, unknown>
  detected_at: number
}

export interface QuarantineEntry {
  id: string
  finding_id: string
  scan_id: string
  device_id: string
  device_label: string
  original_path: string
  container: string | null
  detection_name: string
  classification: Classification
  severity: Severity
  engine: string
  sha256: string
  size: number
  status: 'quarantined' | 'restored' | 'deleted'
  created_at: number
  resolved_at: number | null
  restored_to: string | null
}

export interface EngineStatus {
  name: string
  available: boolean
  version: string
  detail: string
  description: string
}

export interface AgentInfo {
  name: string
  version: string
  loopback_bind: boolean
  accounts_enabled: boolean
  dev_demo: boolean
  engines: EngineStatus[]
  capabilities: {
    quarantine: boolean
    reports: string[]
    scan_modes: string[]
    archive_formats: string[]
    clamav_signature_updates: boolean
  }
  options: Record<string, unknown>
}

export interface AuditRow {
  id: number
  ts: number
  actor: string
  action: string
  detail: string
  ip: string
}

export interface ScanRequestBody {
  device_id: string
  mode: ScanMode
  custom_paths: string[]
}
