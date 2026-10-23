"""Configuration for the USB Shield local scanning agent.

All settings come from environment variables (prefix ``USBSHIELD_``) so that
no secret is ever committed to the repository.  A small, validated subset of
scan-behaviour options can additionally be tuned at runtime through the API;
those overrides are persisted to ``<data_dir>/runtime_config.json`` and are
applied to *new* scans only.
"""
from __future__ import annotations

import json
import os
import threading
from functools import lru_cache
from pathlib import Path
from typing import Any

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

DEFAULT_ALLOWED_ORIGINS = ("http://localhost:3847", "http://127.0.0.1:3847")


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="USBSHIELD_", extra="ignore")

    # --- locations / server -------------------------------------------------
    data_dir: str = "~/.usb-shield"
    bind_host: str = "127.0.0.1"
    port: int = 8765
    allowed_origins: str = ",".join(DEFAULT_ALLOWED_ORIGINS)
    allowed_hosts: str = ""          # extra Host headers (besides loopback)
    extra_device_roots: str = ""     # dev/demo extra scan targets
    dev_demo: bool = False           # enable synthetic demo device endpoint

    # --- optional accounts ---------------------------------------------------
    accounts_enabled: bool = False
    session_secure: bool = True      # Secure flag on session cookies
    session_ttl_seconds: int = 12 * 3600

    # --- ClamAV ---------------------------------------------------------------
    clamd_socket: str = ""           # unix socket path (auto-detected if empty)
    clamd_tcp: str = "127.0.0.1:3310"
    clamav_timeout_seconds: int = 120
    clamav_max_file_bytes: int = 256 * 1024 * 1024

    # --- rate limits -----------------------------------------------------------
    rate_pair_per_minute: int = 5
    rate_login_per_minute: int = 10
    rate_api_per_minute: int = 600

    log_level: str = "INFO"

    # ------------------------------------------------------------------ utils
    @property
    def data_path(self) -> Path:
        return Path(self.data_dir).expanduser()

    @field_validator("bind_host")
    @classmethod
    def _bind_is_loopback_by_default(cls, v: str) -> str:  # noqa: N805
        return v

    def origins(self) -> list[str]:
        return [o.strip() for o in self.allowed_origins.split(",") if o.strip()]

    def extra_hosts(self) -> list[str]:
        return [h.strip() for h in self.allowed_hosts.split(",") if h.strip()]

    def extra_roots(self) -> list[Path]:
        return [Path(p.strip()).expanduser()
                for p in self.extra_device_roots.split(",") if p.strip()]

    def is_loopback_bind(self) -> bool:
        return self.bind_host in ("127.0.0.1", "localhost", "::1")


class RuntimeOptions(BaseSettings):
    """Runtime-tunable scan behaviour (persisted to data_dir, validated)."""
    model_config = SettingsConfigDict(extra="forbid")

    heuristics_enabled: bool = True
    test_signature_engine_enabled: bool = True   # EICAR-style test checks
    archive_scan_enabled: bool = True

    max_depth: int = Field(default=48, ge=1, le=256)
    max_file_bytes: int = Field(default=512 * 1024 * 1024, ge=1024)
    small_file_buffer_bytes: int = Field(default=8 * 1024 * 1024, ge=4096)
    max_entries_per_scan: int = Field(default=600_000, ge=100)
    scan_time_limit_seconds: int = Field(default=2 * 3600, ge=10)
    per_file_seconds: int = Field(default=120, ge=1)

    archive_max_depth: int = Field(default=3, ge=0, le=8)
    archive_max_members: int = Field(default=10_000, ge=1)
    archive_max_member_bytes: int = Field(default=64 * 1024 * 1024, ge=1024)
    archive_max_total_bytes: int = Field(default=1024 * 1024 * 1024, ge=1024)
    archive_max_ratio: int = Field(default=100, ge=2)
    archive_time_budget_seconds: int = Field(default=30, ge=1)

    quick_recent_days: int = Field(default=30, ge=0)


class RuntimeOptionsStore:
    """Loads/saves runtime overrides; thread-safe."""

    def __init__(self, settings: Settings):
        self._settings = settings
        self._lock = threading.Lock()
        self._file = settings.data_path / "runtime_config.json"
        self._opts = self._load()

    def _load(self) -> RuntimeOptions:
        try:
            if self._file.exists():
                raw = json.loads(self._file.read_text(encoding="utf-8"))
                if isinstance(raw, dict):
                    return RuntimeOptions(**{k: v for k, v in raw.items()
                                             if k in RuntimeOptions.model_fields})
        except Exception:
            # Corrupt overrides must never crash the agent; fall back to defaults.
            pass
        return RuntimeOptions()

    def get(self) -> RuntimeOptions:
        with self._lock:
            return self._opts.model_copy()

    def update(self, patch: dict[str, Any]) -> RuntimeOptions:
        with self._lock:
            merged = {**self._opts.model_dump(), **patch}
            self._opts = RuntimeOptions(**merged)  # raises on invalid input
            self._settings.data_path.mkdir(parents=True, exist_ok=True)
            tmp = self._file.with_suffix(".tmp")
            tmp.write_text(json.dumps(self._opts.model_dump(), indent=2),
                           encoding="utf-8")
            os.replace(tmp, self._file)
            try:
                os.chmod(self._file, 0o600)
            except OSError:
                pass
            return self._opts.model_copy()


@lru_cache
def get_settings() -> Settings:
    return Settings()
