from __future__ import annotations

import logging
import sys


def configure_logging(level: str = "INFO", *, bare: bool = False) -> None:
    handler = logging.StreamHandler(sys.stderr)
    if bare:
        handler.setFormatter(logging.Formatter("%(message)s"))
    else:
        handler.setFormatter(
            logging.Formatter(
                "[%(asctime)s] %(levelname)s %(name)s %(message)s", "%Y-%m-%d %H:%M:%S"
            )
        )
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level.upper())

    # Silence noisy third-party HTTP libraries; their per-request INFO/DEBUG lines
    # drown out the dispatcher's own scheduling logs.
    for noisy in ("requests", "urllib3", "docker", "httpx", "httpcore"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
