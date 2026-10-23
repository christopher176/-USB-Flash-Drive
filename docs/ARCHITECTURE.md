# USB Shield — Architecture

## Goals

1. Real detection: signatures (ClamAV) + documented heuristics — never
   fabricated results.
2. Honesty: a device is reported clean **only** when the scan finished with
   full coverage of the requested scope and zero unscannable content.
3. Local first privacy: file contents never leave the user's machine.
4. Browser safety: a malicious website must not be able to drive the local
   scanning agent.

## Components

### Web dashboard (`frontend/`)

React + TypeScript (Vite). Stateless except for the agent token in
`localStorage`. Talks to the agent exclusively at the same-origin `/api`
prefix (the dev server proxies it; production deployments proxy it at the
HTTPS edge — see `docs/DEPLOYMENT.md`). Polls the agent's event cursor for
live scan progress. Receives no file contents.

### Local agent (`agent/usb_shield/`)

FastAPI + uvicorn, bound to loopback (`127.0.0.1:8765`). Single process,
single user (the machine's user). All state under `USBSHIELD_DATA_DIR`
(`~/.usb-shield`, mode `0700`):

```
~/.usb-shield/
├── agent_token            # 0600 – bearer token minted at first run
├── quarantine.key         # 0600 – AES-256 vault key
├── quarantine/*.usq       # 0600 – encrypted quarantine blobs (random names)
├── restored/              # restore inbox (0700)
├── reports/               # saved reports
├── runtime_config.json    # scan-behaviour overrides (validated)
└── usb_shield.db          # scans, findings, quarantine index, users,
                           # sessions, audit log (0600, WAL)
```

### Detection engines (`engines/`)

| Engine | Class | Notes |
|---|---|---|
| ClamAV (`clamav.py`) | signature | Speaks clamd `zINSTREAM` directly (unix socket or TCP); files larger than the stream limit are reported as partially inspected, never silently skipped. Updates via `freshclam`, which verifies ClamAV's digitally signed database. |
| EICAR (`eicar.py`) | signature (test) | Exact eicar.org rule (≤128 bytes, whitespace tail). Proves the pipeline end-to-end; detections flagged `is_test_detection`. |
| Heuristics (`heuristics.py`) | structural/behavioural | Double extensions, disguised PE/ELF (magic bytes), autorun launch directives, `.lnk` headers (+ embedded-string extraction), script markers, bidi/name tricks, atypical executable placement, macro containers in odd locations. Output capped at **suspicious/PUA**. |

Engines implement a small protocol (`scan_buffer` / `scan_stream`) and are
composed per scan from the runtime configuration. Adding an engine (e.g.
YARA) requires no scanner changes.

### Safe traversal (`walker.py`)

- Realpath confinement of every selection to the device root; absolute paths
  and `..` components rejected outright.
- **Never follows symlinks** (`lstat` + `O_NOFOLLOW` open); symlink entries are
  counted and reported as skipped.
- Mount-point jail: directories on a different `st_dev` than the device root
  are not descended.
- Directory-loop guard via `(st_dev, st_ino)`.
- Depth cap; permission errors recorded (and counted) per directory;
  device disconnection detected and fails the scan safely.
- Hidden files are tracked with *inheritance* (content of a hidden folder is
  hidden), and known system areas (`System Volume Information`, `$RECYCLE.BIN`
  …) are flagged like Windows attributes would be (`st_file_attributes` when
  present).

### Safe archive inspection (`archives.py`)

In-memory only (members are never written to disk). Formats: zip, tar,
tar.gz/bz2/xz. Guards: nesting depth, member count, per-member bytes, total
decompressed bytes, declared **and observed** compression ratios, wall-clock
budget. Encrypted, corrupt, oversized and over-limit members produce
"unable to scan" findings; extreme ratios produce a high-severity
"possible archive bomb" finding. Unsupported formats (rar/7z/iso/…) are
reported as unscannable.

### Scanner (`scanner.py`)

- Modes: quick / full / custom (custom targets validated by the walker).
- Two phases: enumeration (for an honest progress estimate) then scanning;
  the estimate is marked incomplete rather than faked for very large devices.
- Every file gets exactly one pipeline: snapshot (no-follow open, small files
  fully buffered, large files header + streamed hashing) → buffer engines →
  ClamAV stream (when available) → archive inspection (when applicable).
  Engine errors become "unable to scan" findings for that file; a file that
  changes under the scanner is retried once then reported, never trusted.
- Cooperative cancellation; time/entry safety limits end the scan as
  **incomplete** with the limit recorded; device removal mid-scan →
  `DEVICE_DISCONNECTED`.
- Final outcome rules (enforced in one place):

  | Condition | outcome |
  |---|---|
  | threats found | `threats_found` |
  | 0 threats, ≥1 unable/partial/dir-failure | `no_threats_with_gaps` |
  | 0 threats, full coverage | `clean` |
  | cancelled / failed / safety limit | `incomplete` |

### Quarantine (`quarantine.py`)

Copy → verify hash matches the scan record → AES-256-GCM encrypt (random
nonce, AAD binds `sha256|path`) → durable write (0600, fsync) → unlink the
original. Restore decrypts, re-verifies the hash, and writes with `O_EXCL`
(never overwrites) to the original device location or the local restore
inbox. Destroy unlinks the blob after confirmation. All actions audited.
Archive members cannot be individually quarantined/deleted (safe error with
guidance). No automatic deletion exists anywhere in the codebase.

### API security (`security.py`, `api/`)

- `POST /api/pair`: loopback-only and rate-limited; registers a **paired
  client credential** (id + secret, secret stored SHA-256 only) and returns
  it together with a first **short-lived access token** (default TTL
  20 minutes, in-memory only).
- `POST /api/token`: exchanges a paired credential for a fresh short-lived
  token (rate-limited). The dashboard refreshes automatically.
- Every other route (except `GET /api/health`): `Authorization: Bearer` with
  constant-time compare against live short-lived tokens; failures audited.
  The long-lived root token (`~/.usb-shield/agent_token`, `0600`) is accepted
  for local admin/CLI use and never needs to leave the data directory.
- Mutations additionally require `X-USBShield-Client: usb-shield-web`
  (cross-origin pages cannot set custom headers without a CORS preflight,
  which the allowlist denies).
- Origin allowlist enforced server-side; `Host` allowlist enforced in
  middleware (DNS-rebinding defence). CORS answers preflights only for the
  allowlist.
- Security headers on everything: strict CSP (`default-src 'none'`), nosniff,
  DENY framing, no-store, no-referrer, permissions policy. No docs/debug
  endpoints in production builds.
- Optional accounts (`auth.py`): Argon2id (RFC 9106 parameters), constant
  behaviour for unknown users, automatic hash upgrades, **TOTP mandatory for
  admins** (enrolment enforced before a session exists), sessions server-side
  with expiry; cookies HttpOnly + SameSite=Strict (+Secure behind HTTPS).
- Rate limits: pairing, login, signature updates. Audit log: every auth and
  sensitive action (scans, quarantine, deletes, config changes, report
  generation, auth events, rate-limit trips).

## Request flows

**Pairing** — dashboard calls `POST /api/pair` via the same-origin proxy;
the agent verifies the TCP peer is loopback and rate limits. Response is not
readable cross-origin (CORS), so a hostile page cannot pair through a
victim's browser.

**Scan** — `POST /api/scans` validates the device id against the enumerated
allowlist (system drives are never listed, so they cannot be requested),
validates custom paths, enqueues the job. The dashboard then polls
`GET /api/scans/{id}/events?since=N` (monotonic cursor) for progress and the
terminal record, and fetches findings once `done`.

**Threat action** — review → `POST /api/quarantine` (or
`POST /scans/{id}/findings/{fid}/delete` with `{confirm:true}`). Sidebar
vault operations require `{confirm:true}` bodies; deletions write audit
entries.

## What the agent never does

- Execute or render scanned content (no subprocess for file handling;
  `freshclam` runs with a fixed argv, no shell).
- Follow symlinks, cross mounts inside a device, or accept paths outside the
  selected device.
- Transmit file content anywhere (quarantine stays local and encrypted).
- Claim clean with gaps. Claim "malicious" from heuristics. Auto-delete.
