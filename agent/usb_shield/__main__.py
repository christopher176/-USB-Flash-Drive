"""Entry point: ``python -m usb_shield`` starts the local agent."""
from __future__ import annotations

import logging
import sys


def main() -> int:
    import uvicorn

    from .api.app import create_app
    from .config import get_settings

    cfg = get_settings()
    logging.basicConfig(level=getattr(logging, cfg.log_level.upper(), logging.INFO),
                        format="%(asctime)s %(levelname)s %(name)s %(message)s")
    log = logging.getLogger("usb_shield")
    if not cfg.is_loopback_bind():
        log.warning("agent is NOT bound to loopback (%s) - this is dangerous; "
                    "set USBSHIELD_BIND_HOST=127.0.0.1 unless you know otherwise",
                    cfg.bind_host)
    app = create_app(cfg)
    token_file = cfg.data_path / "agent_token"
    log.info("USB Shield agent listening on http://%s:%d (token file: %s)",
             cfg.bind_host, cfg.port, token_file)
    log.info("Pair from the web UI (same machine) or read the token file; "
             "keep the token secret.")
    uvicorn.run(app, host=cfg.bind_host, port=cfg.port, log_level=cfg.log_level.lower())
    return 0


if __name__ == "__main__":
    sys.exit(main())
