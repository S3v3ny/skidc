from __future__ import annotations

import abc
import re
import shlex
import uuid
from dataclasses import dataclass

from skidc.dispatcher.config import WorkerConfig


@dataclass(slots=True)
class DriverResult:
    argv: list[str]
    session: str | None = None


class WorkerDriver(abc.ABC):
    """A driver adapts one agent CLI (Claude Code, Codex, ...) into the dispatcher's
    uniform contract: build a healthcheck, build the execute command, optionally
    resume the same session for a conclude pass, and extract the model's text reply.

    The model itself is NOT hard-coded here. Which LLM a driver actually talks to is
    decided entirely by the worker's `env` (model name + base URL + key). That is the
    seam that lets a `claudecode` worker drive DeepSeek and a `codex` worker drive Qwen."""

    type_name: str

    def supports_conclude(self) -> bool:
        return True

    def prepare_session(self) -> str | None:
        return None

    def build_startup_healthcheck(self, worker: WorkerConfig) -> list[str]:
        return self.build_healthcheck(worker)

    def describe_startup_healthcheck(self, worker: WorkerConfig) -> str:
        return shlex.join(self.build_startup_healthcheck(worker))

    @abc.abstractmethod
    def build_healthcheck(self, worker: WorkerConfig) -> list[str]:
        raise NotImplementedError

    @abc.abstractmethod
    def build_execute(self, worker: WorkerConfig, prompt: str, session: str | None) -> DriverResult:
        raise NotImplementedError

    @abc.abstractmethod
    def build_conclude(self, worker: WorkerConfig, prompt: str, session: str) -> list[str]:
        raise NotImplementedError

    def extract_session(self, session: str | None, stdout: str, stderr: str) -> str | None:
        return session

    def extract_response_text(self, stdout: str, stderr: str) -> str:
        return stdout


class SeedSessionDriver(WorkerDriver):
    """Driver whose CLI accepts a caller-provided session id (e.g. Claude Code)."""

    def prepare_session(self) -> str | None:
        return str(uuid.uuid4())


class RegexSessionDriver(WorkerDriver):
    """Driver whose CLI prints a session id to stderr we must scrape (e.g. Codex)."""

    session_pattern = re.compile(r"session id:\s*([0-9a-fA-F-]+)")

    def extract_session(self, session: str | None, stdout: str, stderr: str) -> str | None:
        if session:
            return session
        match = self.session_pattern.search(stderr)
        if match:
            return match.group(1)
        return None
