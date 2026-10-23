# USB Shield — Privacy Policy (template)

*Effective date: 2026-10-23. Adapt contact details before publishing.*

USB Shield is designed around one rule: **your files stay on your computer.**
This document explains exactly what the software stores, where, and why.

## 1. What USB Shield collects

USB Shield stores the following data **locally on your computer**, inside
`~/.usb-shield` (or the directory named by `USBSHIELD_DATA_DIR`):

| Data | Purpose | Contains |
|---|---|---|
| Agent token | Authenticate the dashboard to the local agent | random secret |
| Quarantine key | Encrypt the quarantine vault | random secret |
| Quarantine vault | Isolate threats you chose to quarantine | AES-256-GCM encrypted copies of the quarantined files, original paths, SHA-256, detection names |
| Scan history & reports | Review results later | device labels, file paths, hashes, verdicts, counters, engine versions |
| Audit log | Security accountability | actions taken (login attempts, scans, quarantine/restore/delete, config changes), timestamps, local IPs |
| Runtime configuration | Your scan-behaviour settings | limits and toggles |
| Optional accounts | Sign-in when accounts are enabled | username, Argon2id password hash, TOTP secret (admins), server-side sessions |

## 2. What USB Shield does **not** collect

- No telemetry, analytics, crash reports, or usage tracking of any kind.
- No file contents are transmitted anywhere. Scanning is performed locally.
- Quarantined files remain local and encrypted; they are never uploaded.
- No automatic submissions to VirusTotal or any other third-party analysis
  service.
- No device fingerprinting, cookies for tracking, or advertising identifiers.

## 3. Network communication

- The dashboard talks to the local agent on your own machine (loopback) via
  an authenticated channel.
- If you install ClamAV, its updater (`freshclam`) contacts ClamAV's servers
  to download **signature databases only**, using ClamAV's verified update
  mechanism. This is the only routine internet traffic, and only when you
  install/enable ClamAV.
- If the dashboard is hosted as a website (see DEPLOYMENT.md), it is served
  over HTTPS; scan data remains on the local agent.

## 4. Data retention & deletion

You can erase local data at any time:

- **History & Reports → Delete all history** removes scan records, findings
  and saved reports.
- Quarantine → *Destroy* permanently deletes the encrypted copy of a
  quarantined file.
- Deleting `~/.usb-shield` removes everything (token, key, vault, database).
  Note: deleting the key renders any remaining vault blobs unrecoverable by
  design.

## 5. Security of stored data

- Data directory permissions `0700`; database, key and token files `0600`.
- Vault blobs: AES-256-GCM, random filenames, non-executable.
- Passwords (optional accounts): Argon2id; administrator accounts require
  TOTP MFA.
- See `docs/THREAT_MODEL.md` for the full security analysis.

## 6. Children's privacy

USB Shield processes no personal data beyond what is listed above and is not
directed at children.

## 7. Changes & contact

Changes to this policy will be noted in the project repository. Contact:
`security@example.com` *(replace before publishing)*.
