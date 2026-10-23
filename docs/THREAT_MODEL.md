# USB Shield — Threat Model

## Scope & assets

| Asset | Why it matters |
|---|---|
| User's files on the USB device | Must not be deleted, exfiltrated, or modified except by confirmed user action |
| Host computer | The agent has filesystem reach into the selected device; it must not gain reach beyond it |
| Agent token | Full control of the local API |
| Quarantine vault & key | Contains live threats; must not execute or leak |
| Scan history / reports | Sensitive filenames & hashes |
| Optional web accounts | Argon2id hashes, TOTP secrets, session tokens |

## Adversaries

1. **Malicious websites** in the user's browser trying to trigger local scans,
   read results, or delete/quarantine files via the user's agent.
2. **DNS rebinding / local-network attackers** pointing a hostile origin at
   `127.0.0.1`.
3. **Malicious device content**: zip bombs, pathological nesting, symlink
   traps, files that change under the scanner, crafted filenames (markup,
   bidi), autorun launchers.
4. **Network attackers** between the user and a hosted dashboard (when the UI
   is deployed on a domain).
5. **Credential attackers** against optional accounts (phishing, stuffing,
   offline hash cracking).
6. **Supply-chain attackers** (compromised dependencies / signature feeds).

## Trust boundaries

```
browser UI ──(same-origin /api, TLS at edge)──► local agent ──► device FS
     ▲                                           │  └──► ~/.usb-shield (vault, DB)
     └──────── any OTHER origin ──✗ (denied) ────┘
```

The agent assumes *anything arriving over HTTP* may be hostile and
authenticates it. The OS filesystem under the device mount is untrusted data.

## Threats → mitigations

| # | Threat | Mitigation |
|---|---|---|
| T1 | Website calls `http://127.0.0.1:8765/api/...` from the victim's browser | Short-lived bearer token required (unknown to the website, refreshed via paired credentials); Origin allowlist check; custom-header CSRF requirement triggers a preflight CORS denies; pairing is loopback-only and its response is unreadable cross-origin |
| T2 | DNS rebinding to bypass same-origin | `Host` header allowlist middleware (rebinding presents a foreign Host) + loopback-only bind |
| T3 | Token theft via XSS in the dashboard | Strict CSP (`script-src 'self'`, no inline), React output encoding, no third-party scripts, reports rendered with escaping + restrictive CSP; dependency pinning + `make audit` |
| T4 | CSRF (classic, non-browser clients) | SameSite=Strict cookies for account sessions; agent API uses bearer headers, not ambient cookies, and requires the CSRF header |
| T5 | Path traversal into host files (`../../etc`) | Allowlist device enumeration (system drives never selectable), `resolve_within` rejects absolute/`..`/NUL, realpath confinement, per-scan confinement checks |
| T6 | Symlink escapes (device link → host file) | `lstat` enumeration, `O_NOFOLLOW` opens, symlink selections rejected, link members in archives never followed, mount-point jail via `st_dev` |
| T7 | Archive bomb exhausting CPU/RAM/disk | No disk extraction; depth/member/byte/ratio/time limits; bombs flagged high-severity; over-limit archives reported as gaps |
| T8 | Malware executing during scan | Nothing is executed or rendered; content is bytes to engines only; vault blobs are encrypted, random-named, 0600, non-executable |
| T9 | Auto-deletion / silent data loss | No automatic deletion anywhere; delete & restore require explicit `{confirm:true}`; quarantine removes the original only after the encrypted copy is durable and hash-checked |
| T10 | False "clean" claims | Central outcome computation (clean ⇒ completed + full coverage + zero gaps); quick scan scope always disclosed; partial/unable/limited states surfaced in UI, report text, and JSON |
| T11 | MITM against hosted dashboard | HTTPS with modern TLS at the edge (see deployment), HSTS, secure cookies; agent itself stays loopback so there is no agent traffic to intercept |
| T12 | Password compromise (accounts) | Argon2id (m=64 MiB, t=3, p=4), constant-shape failures, per-IP rate limits, **TOTP mandatory for admins**, automatic hash upgrades, server-side session expiry |
| T13 | Tampered quarantine blob | AES-256-GCM with key at 0600; AEAD tag + SHA-256 verification; tamper → restore refused |
| T14 | Malicious signature feed | `freshclam` verifies ClamAV's digitally signed databases; we never implement our own update channel |
| T15 | Malicious config injection | Runtime options schema-validated (pydantic, ranges, `extra="forbid"`); env-only base config; no object injection paths |
| T16 | Log/audit abuse | Audit detail capped, treated as text, HTML-escaped in any rendering |
| T17 | Device removed mid-scan corrupting results | Liveness probing + `DeviceDisconnected` → scan fails as incomplete; no partial-clean claim |
| T18 | Insider reading another user's agent data | Data dir 0700, DB 0600, key 0600, single-user loopback design; OS accounts isolate users |

## Residual risks (accepted / documented)

- **Firmware-level threats** (BadUSB, device controller malware) are out of
  scope for file scanning. Documented in LIMITATIONS.md.
- A local process running as the user could read `~/.usb-shield` (any local
  AV design shares this; mitigations are OS-level).
- Without ClamAV, coverage is heuristic + test signature only — displayed
  prominently, never hidden.
- Heuristics can produce false positives by design; they are labelled
  "suspicious", never "malicious".
- Denial of service of the loopback agent by other local processes is
  possible (same for all localhost security tools).
