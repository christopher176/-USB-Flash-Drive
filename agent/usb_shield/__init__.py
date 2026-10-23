"""USB Shield - secure USB flash-drive virus detection and removal.

Package layout:
    config      - environment-driven settings (secrets stay out of the repo)
    models      - pydantic wire/DB models shared by every layer
    walker      - safe filesystem traversal (no symlink escapes, mount jail)
    archives    - safe in-memory archive inspection with resource limits
    engines     - pluggable detection engines (eicar test sig, heuristics, clamav)
    scanner     - scan orchestration, progress, cancellation, outcomes
    quarantine  - encrypted, access-controlled quarantine vault
    store       - SQLite persistence (scans, findings, quarantine, users, audit)
    auth        - optional user accounts: Argon2id + TOTP MFA + sessions
    drives      - removable-device enumeration and the system-drive guard
    security    - bearer tokens, pairing, rate limiting, header middleware
    api/        - FastAPI application and routers
"""

__version__ = "0.1.0"

APP_NAME = "USB Shield"
