# USB Shield — Deployment Guide

## 1. Development

```bash
make setup && make setup-frontend
make dev-agent      # agent on http://127.0.0.1:8765
make dev-frontend   # dashboard on http://localhost:3847 (proxies /api)
make test           # full test-suite
```

Development defaults (set by `scripts/dev-agent.sh`) enable the demo
endpoint and allow the Vite origin. **Do not use these settings in
production.**

## 2. Production model

```
        user browser
             │  1. HTTPS (TLS 1.2+/1.3, HSTS)
             ▼
   edge / reverse proxy ── serves static dashboard build
             │  2. /api/* proxied (same origin) over loopback
             ▼
   USB Shield agent (127.0.0.1:8765, on the SAME machine the USB drive
   is attached to — per-user, least privilege)
```

Key properties:

- The agent **stays on the machine with the USB port**, bound to loopback.
  Never expose it to a network. If your dashboard is hosted remotely, the
  agent runs on each user's own computer and the *hosted website does not
  proxy to it* — in that case the user runs the local dashboard too, or the
  site points them at their own agent. Do not bridge a remote origin to the
  loopback agent.
- Serve the dashboard build (`frontend/dist`) over HTTPS. If you host the
  dashboard on the same machine as the agent, proxy `/api` to the loopback
  agent as the dev server does; add the public origin to
  `USBSHIELD_ALLOWED_ORIGINS` and the public hostname to
  `USBSHIELD_ALLOWED_HOSTS`.

## 3. Agent service (systemd, Linux)

`deploy/usb-shield-agent.service` (user service) — run as the desktop user,
least privilege:

```ini
[Unit]
Description=USB Shield local scanning agent
After=default.target

[Service]
Type=simple
WorkingDirectory=/opt/usb-shield/agent
Environment=USBSHIELD_DATA_DIR=%h/.usb-shield
Environment=USBSHIELD_BIND_HOST=127.0.0.1
Environment=USBSHIELD_PORT=8765
Environment=USBSHIELD_ALLOWED_ORIGINS=https://usbshield.example.com
Environment=USBSHIELD_SESSION_SECURE=true
ExecStart=/opt/usb-shield/agent/.venv/bin/python -m usb_shield
Restart=on-failure
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=%h/.usb-shield /media /run/media
ProtectKernelTunables=true
ProtectControlGroups=true
RestrictSUIDSGID=true
LockPersonality=true

[Install]
WantedBy=default.target
```

```bash
systemctl --user daemon-reload
systemctl --user enable --now usb-shield-agent
```

Notes:

- `ReadWritePaths` limits write access to the data dir and removable-media
  mount points (needed for quarantine/delete/eject).
- On Windows, ship the agent as a signed desktop service (MSIX/service
  wrapper). On macOS, use a LaunchAgent with the sandbox profile allowing
  `/Volumes`.

## 4. Reverse proxy (dashboard + /api on one HTTPS origin)

`deploy/nginx.conf.example` (Caddy works too — it manages TLS for you):

```nginx
server {
    listen 443 ssl;
    http2 on;
    server_name usbshield.example.com;

    ssl_certificate     /etc/letsencrypt/live/usbshield.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/usbshield.example.com/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers off;    # TLS1.3; TLS1.2 uses the modern default suite

    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains" always;
    add_header X-Content-Type-Options nosniff always;
    add_header Referrer-Policy no-referrer always;
    add_header X-Frame-Options DENY always;

    root /var/www/usb-shield/dist;
    try_files $uri /index.html;

    location /api/ {
        proxy_pass http://127.0.0.1:8765;
        proxy_http_version 1.1;
        proxy_set_header Host 127.0.0.1:8765;   # satisfies the agent allowlist
        proxy_set_header X-Forwarded-For "";    # don't leak client IPs downstream
        # Origin header passes through unchanged; the agent enforces its allowlist
        limit_req zone=usbshield burst=20 nodelay;
    }
}
```

Update the agent:

```
USBSHIELD_ALLOWED_ORIGINS=https://usbshield.example.com
USBSHIELD_ALLOWED_HOSTS=127.0.0.1:8765          # Host as set by the proxy
```

> Important: `proxy_set_header Host 127.0.0.1:8765;` rewrites Host to the
> loopback value. The agent still enforces the **Origin** allowlist, which is
> what distinguishes the real UI origin from an attacker page.
>
> **Pairing stays local.** Because the reverse proxy reaches the agent from
> loopback, a publicly proxied `/api/pair` would answer for *anyone* — the
> example config therefore blocks it at the edge. Pair by browsing the
> dashboard from the machine itself (e.g. `http://localhost:3847` in dev or a
> local SOCKS tunnel), or read `~/.usb-shield/agent_token` and paste it in the
> Connect screen.

## 5. Optional accounts

Enable only when the dashboard is multi-user/hosted:

```
USBSHIELD_ACCOUNTS_ENABLED=true
USBSHIELD_SESSION_SECURE=true     # requires HTTPS
```

The first registered user becomes administrator and **must enrol TOTP**
before any session is issued. Registration closes automatically afterwards;
additional users are created by an administrator (viewer role).

## 6. Signature updates

- The agent offers Settings → "Update ClamAV signatures", which runs
  `freshclam` (fixed argv, rate-limited, audited).
- Also schedule it out-of-band: `systemctl enable --now clamav-freshclam`
  (Debian) or a cron/timer entry. ClamAV authenticates its database
  (`*.cvd`/`*.cdiff` are digitally signed by Cisco Talos).

## 7. Dependency & vulnerability management

```bash
make audit        # pip-audit + npm audit
```

Run in CI on every change (see `.github/workflows/ci.yml`). No secrets are
committed; the agent token/key are generated at first run with `0600`
permissions. Rotate the token by deleting `~/.usb-shield/agent_token` and
re-pairing.

## 8. Hardening checklist (production)

- [ ] `USBSHIELD_BIND_HOST=127.0.0.1` (default) — never `0.0.0.0`
- [ ] `/api/pair` blocked at the public edge (never proxy it to the internet)
- [ ] `USBSHIELD_DEV_DEMO=false` (default)
- [ ] Allowed origins/hosts restricted to your real dashboard origin(s)
- [ ] TLS 1.2+/1.3 only, HSTS at the edge, modern ciphers
- [ ] `USBSHIELD_SESSION_SECURE=true` when accounts are enabled
- [ ] systemd sandboxing enabled (unit above)
- [ ] ClamAV daemon running; `freshclam` timer enabled
- [ ] `make audit` clean in CI; renovate/dependabot enabled
- [ ] No debug/docs endpoints (the app disables them by default — verify)
- [ ] Audit-log review procedure in place (`/api/audit`)
