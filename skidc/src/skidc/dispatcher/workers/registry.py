from __future__ import annotations

from skidc.dispatcher.workers.adapters import ClaudeCodeDriver, CodexDriver, MockDriver
from skidc.dispatcher.workers.base import WorkerDriver


DRIVERS: dict[str, WorkerDriver] = {
    "claudecode": ClaudeCodeDriver(),
    "codex": CodexDriver(),
    "mock": MockDriver(),
}


def get_driver(name: str) -> WorkerDriver:
    return DRIVERS[name]
