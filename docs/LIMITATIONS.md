# USB Shield — Scanning Limitations (read before relying on results)

USB Shield is deliberately honest about what a scan does and does not prove.
The dashboard, text reports and JSON reports repeat these points wherever a
result is displayed.

## What a "clean" outcome means — and does not mean

A **clean** outcome means: every file in the requested scope was fully and
successfully inspected by the engines listed in the report, and none was
detected. It does **not** prove the device is free of all malware:

- **No scanner detects everything.** New (zero-day), targeted, or encrypted
  payloads may have no signature and no heuristic indicators.
- **Firmware threats** (e.g. BadUSB reprogrammed device firmware) live outside
  the filesystem entirely and cannot be detected by file scanning.
- **Encrypted archives** cannot be opened; they are reported as *unable to
  scan*, and the scan outcome is degraded accordingly.
- **Permission-protected** files/folders the OS refuses to let the agent read
  are reported as *unable to scan*.
- **Active malware on the host** could theoretically tamper with any
  user-space scanner. USB Shield assumes the host is not already compromised.

## Engine coverage

| Situation | Coverage |
|---|---|
| ClamAV installed & running | Real, continuously updated malware signatures + heuristics |
| ClamAV absent | **Heuristics + EICAR test signature only.** The header pill in the dashboard shows "ClamAV not detected". Install `clamav-daemon` for protection. |

Heuristics describe *suspicious characteristics*; false positives are
expected occasionally (e.g. a legitimately double-named file). They are never
presented as confirmed infections.

## Format / size boundaries (all visible in reports)

- Archives inspected: **zip, tar, tar.gz, tar.bz2, tar.xz**. rar, 7z, iso,
  cab and plain gzip members are reported *unable to scan (unsupported
  format)* rather than silently passed.
- Archive bombs are contained by limits (nesting depth, member count/size,
  total bytes, ratio, time); when a limit triggers, the archive is reported
  partially inspected.
- Files above the size limit are header/metadata-inspected and reported as
  *partially scanned*; items past the antivirus stream limit are likewise
  surfaced.
- Quick Scan covers high-risk locations and file types **only**. The UI and
  reports state this explicitly.

## Filesystem realities

- **Symlinks are never followed** (counted as skipped). A malicious file
  reachable only via a symlink will not be read through the link; the target
  itself is still scanned if it lives on the device.
- Files that **change during scanning** are retried once, then reported
  *unable to scan*.
- Very large devices may exceed the entry/time safety limits; the scan then
  stops and is reported **incomplete**, never clean.
- On non-Windows systems, Windows "hidden/system" attributes don't exist;
  USB Shield uses dotfiles and known system-area names as the equivalent
  classification (and reads `st_file_attributes` where the OS provides it).

## Web-only prototype caveat

If you ever serve the dashboard without the local agent (not the default
setup), the UI cannot enumerate or scan whole USB drives — browsers
intentionally cannot do that. In such a deployment you may only scan files
the user explicitly selects; **never imply complete USB-drive coverage** from
a browser alone. USB Shield's full-coverage claims apply strictly to the
agent-backed configuration described in `docs/ARCHITECTURE.md`.

## Eject & deletion caveats

- Eject is best-effort using OS tools (`udisksctl`, `diskutil`, `umount`);
  the UI reports exactly what happened. Verify the OS agrees before removing
  the device.
- Delete permanently unlinks files; it is **not** a forensic wipe. Quarantine
  and full-disk imaging tools are the appropriate choices when forensic
  preservation matters.
