# USB Shield

**Secure USB flash-drive virus detection and removal.** USB Shield scans
removable drives for malware, trojans, spyware, ransomware droppers, malicious
scripts, disguised executables, autorun abuse and archive bombs — including
files tucked away in hidden folders, system directories and nested archives
that casual scans miss.

Everything runs **locally on your computer**: file contents never leave the
machine.

```
┌──────────────────────────────────────────────────────────────────────┐
│  Browser (React + TypeScript dashboard)                                │
│  • device selection • scan modes • live progress • findings review     │
│  • quarantine / restore / delete • history & reports • audit log       │
└───────────────┬──────────────────────────────────────────────────────┘
                │ HTTPS (production) or same-origin dev proxy
                │ bearer token + Origin allowlist + CSRF header + loopback pairing
┌───────────────▼──────────────────────────────────────────────────────┐
│  USB Shield local agent (Python / FastAPI, loopback-only)            │
│  • removable-device enumeration (system drives are never exposed)      │
│  • safe traversal: no symlink escapes, mount-point jail, loop guard    │
│  • engines: ClamAV (real signatures) + EICAR test sig + heuristics     │
│  • safe archive inspection: zip/tar, bomb & nesting limits             │
│  • AES-256-GCM quarantine vault • audit log • reports                  │
└───────────────┬──────────────────────────────────────────────────────┘
                │ read-only, least-privilege filesystem access
        ┌───────▼───────┐
        │  USB device   │
        └───────────────┘
```

## Quickstart

Requirements: **Python ≥ 3.10**, **Node.js ≥ 20**, and (recommended) **ClamAV**
for full malware signature coverage.

```bash
# 1. Install the scanning agent's dependencies
make setup                 # creates agent/.venv and installs python deps

# 2. Start the local agent (terminal 1)
make dev-agent             # http://127.0.0.1:8765  (loopback only)

# 3. Start the web dashboard (terminal 2)
make dev-frontend          # http://localhost:3847

# 4. Open http://localhost:3847 and click "Pair with local agent".
#    Insert a USB drive, select it, choose a scan mode, press "Scan USB".
```

Without a physical USB device you can still try the full pipeline: the
dashboard offers **"Create synthetic demo device (test data)"** while
`USBSHIELD_DEV_DEMO=true` (set by `make dev-agent`). It builds a folder of
harmless content — clean files, the standard **EICAR test string** (the
industry-accepted safe way to prove AV detection works), suspicious scripts
and archive samples — and scans it for real.

## Scan modes

| Mode | What it covers |
|---|---|
| **Quick Scan** | Device root, hidden & system folders, and high-risk file types (executables, scripts, shortcuts, autorun, archives, macro documents). *Not* a substitute for a full scan — the UI says so explicitly. |
| **Full Deep Scan** | Recursive inspection of **every accessible file**, including hidden folders, system directories and nested archives. |
| **Custom Scan** | Only the folders/files you pick on the device (validated against path traversal). |

## What the results mean

The interface strictly distinguishes:

- **Malicious** — confirmed match to a known signature (ClamAV signature, or
  the EICAR *test* signature, which is labelled as a test detection).
- **Suspicious** — heuristic indicators (disguised executables, autorun
  launchers, script abuse, misleading names). Never claimed to be confirmed
  infections.
- **Potentially unwanted** — macro-capable documents in odd places, bare
  autorun configs, and similar review-worthy items.
- **Clean** — the file was successfully inspected, nothing found.
- **Unable to scan** — encrypted/corrupt/unsupported/over-limit/unreadable
  files. A device is **never** reported clean while any of these exist, or
  while a scan was interrupted.

## Threat management

- **Quarantine** — copies the file off the device into an AES-256-GCM
  encrypted vault (`~/.usb-shield/quarantine`, `0700`), then unlinks the
  original. Blobs can't execute. Hash-verified restore (original location or
  a local inbox) and confirmed permanent destruction are supported.
- **Delete** — permanently removes a detected file from the device, only after
  explicit confirmation in a second dialog step.
- **Reports** — JSON / TXT / HTML reports (all dynamic values escaped) plus a
  full local scan history with counters and engine versions.
- **Eject** — best-effort safe device eject after scanning.

## Security model (summary — see `docs/THREAT_MODEL.md`)

- Agent binds to loopback only; **pairing is loopback-only** and rate-limited.
- **Short-lived access tokens** (20 min, auto-refreshing, memory-only) protect
  every API route; the long-lived admin token never leaves the data
  directory; constant-time comparisons; files `0600`.
- **Origin allowlist**, **Host-header allowlist** (DNS-rebinding guard), and a
  required custom header on mutations (CSRF a cross-origin site cannot mint).
- Optional user accounts: **Argon2id** hashing (RFC 9106 parameters) and
  **mandatory TOTP MFA for administrators**; HttpOnly+SameSite=Strict cookies.
- Rate limits on pairing/login/signature-update; full audit log of sensitive
  actions; security headers + strict CSP; no debug/admin surface in production.
- Filenames and file content are always treated as untrusted: output encoding
  everywhere, no file execution ever, path-traversal and symlink-escape
  protection baked into the walker.
- Signature updates go through ClamAV's own verified updater (`freshclam`).

## ClamAV installation (recommended)

ClamAV supplies the real, continuously-updated malware signature database.
Without it the agent runs identically, but coverage is limited to the built-in
test-signature and heuristic engines — the dashboard shows this honestly.

```bash
# Debian / Ubuntu
sudo apt install clamav-daemon
sudo systemctl enable --now clamav-daemon
sudo freshclam            # initial signature download

# macOS (Homebrew)
brew install clamav && brew services start clamav

# The agent auto-detects clamd. Verify in the dashboard header:
# the pill switches to "ClamAV <version>". Update signatures any time
# from Settings → "Update ClamAV signatures".
```

## Testing

```bash
make test                  # python test-suite (agent/)
make build                 # type-check + production build of the dashboard
```

The suite uses **synthetic data and the EICAR standard test file only — never
live malware** — and covers: EICAR boundary rules, heuristic rules, hidden/
system/nested traversal, symlink-escape and mount-jail prevention, archive
detection/bombs/limits/encryption/malformation, scan honesty (oversized,
unreadable, and mid-scan-modified files are never called clean), device
disconnect mid-scan, cancellation, API auth/CSRF/Origin/Host/rate-limit
defences, pairing confinement, quarantine encrypt→restore→delete workflows
(including tamper detection), report XSS escaping, Argon2id storage, TOTP
(RFC 6238 vectors), admin-MFA enforcement, cookie flags, and history deletion.

## Configuration

All configuration is via environment variables (see `.env.example`). Key ones:

| Variable | Default | Purpose |
|---|---|---|
| `USBSHIELD_DATA_DIR` | `~/.usb-shield` | tokens, vault, DB, reports, audit log |
| `USBSHIELD_BIND_HOST` | `127.0.0.1` | **keep loopback**; the agent is local-only |
| `USBSHIELD_PORT` | `8765` | agent port |
| `USBSHIELD_ALLOWED_ORIGINS` | `http://localhost:3847,http://127.0.0.1:3847` | browser origins allowed to call the agent |
| `USBSHIELD_ALLOWED_HOSTS` | – | extra allowed `Host` headers behind a proxy |
| `USBSHIELD_ACCOUNTS_ENABLED` | `false` | optional web-tier accounts (Argon2id+TOTP) |
| `USBSHIELD_SESSION_SECURE` | `true` | Secure flag on session cookies (needs HTTPS) |
| `USBSHIELD_CLAMD_SOCKET`/`USBSHIELD_CLAMD_TCP` | auto / `127.0.0.1:3310` | ClamAV daemon endpoints |
| `USBSHIELD_DEV_DEMO` | `false` | synthetic demo device (development only) |

Runtime scan limits (depth, archive caps, bomb ratios, time budgets, engine
toggles) are adjustable from the dashboard's Settings page and are persisted
under the data directory.

## Production deployment

See `docs/DEPLOYMENT.md`. In short: the web dashboard is served over HTTPS
(modern TLS), the agent stays on each user's machine bound to loopback, and
the browser reaches the agent only through the authenticated, origin-checked
channel described above. A hardened `systemd` unit and a reverse-proxy example
are included under `deploy/`.

## Documentation

| Document | Contents |
|---|---|
| `docs/ARCHITECTURE.md` | Components, data flow, design invariants, engine pipeline |
| `docs/THREAT_MODEL.md` | Assets, adversaries, mitigations, residual risks |
| `docs/PRIVACY.md` | Privacy policy (template) — what is collected, where, and why |
| `docs/LIMITATIONS.md` | **Read this.** Honest limits of the scanning approach |
| `docs/DEPLOYMENT.md` | Development & production deployment, hardening checklist |

## Repository layout

```
agent/        USB Shield local scanning agent (Python, FastAPI)
  usb_shield/ walker, archives, engines (clamav/eicar/heuristics), scanner,
              quarantine, auth, security middleware, API routers, reports
  tests/      pytest suite (synthetic data + EICAR only)
frontend/     React + TypeScript dashboard (Vite)
docs/         architecture, threat model, privacy, limitations, deployment
deploy/       systemd unit, reverse-proxy examples
scripts/      dev runners, end-to-end demo, security audit helper
```

## License / safety

USB Shield performs **read-only inspection** of selected devices plus
explicitly-confirmed quarantine/delete operations. It never executes,
uploads, or transmits scanned content. The EICAR string included in test
fixtures is the harmless, industry-standard antivirus *test* file published
by eicar.org for exactly this purpose.
