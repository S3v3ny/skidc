"""Load and parse the XBOW Validation Benchmarks catalog.

Each benchmark dir holds:
  - benchmark.json : metadata (name, level, tags, description, win_condition)
  - docker-compose.yml : one or more services; exactly one publishes a port (`ports:`)
    and is the HTTP entry point the agent attacks. Others (db, internal-service) only
    `expose:` ports and are reached internally by the app.

We need, per benchmark: its id (= dir name), metadata, and the entry service's name +
the container-INTERNAL port. On the shared `skidc-bench` docker network the worker
reaches the app at `http://<alias>:<internal_port>` (alias = lowercased benchmark id),
so the published host port is irrelevant — we only care about the container port.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

import yaml


@dataclass
class Benchmark:
    id: str                      # e.g. "XBEN-001-24" (the directory name)
    dir: Path
    name: str
    description: str
    level: str                   # "1" | "2" | "3"
    tags: list[str] = field(default_factory=list)
    win_condition: str = "flag"
    entry_service: str = ""      # compose service that publishes a port
    entry_port: int = 80         # container-internal port of that service

    @property
    def alias(self) -> str:
        """DNS name the worker uses on the shared network."""
        return self.id.lower()

    @property
    def target_url(self) -> str:
        return f"http://{self.alias}:{self.entry_port}"


def _internal_port(port_entry) -> int | None:
    """Extract the container-internal port from one compose `ports:` item.

    Handles: 80, "80", "8000:80", "8080:80", "127.0.0.1:8000:80",
    {"target": 80, "published": 8080}.
    The internal port is the LAST colon-separated field (long syntax: 'target')."""
    if isinstance(port_entry, dict):
        target = port_entry.get("target")
        return int(target) if target is not None else None
    s = str(port_entry).strip().strip('"').strip("'")
    if not s:
        return None
    # strip a trailing /tcp or /udp protocol suffix
    s = s.split("/", 1)[0]
    last = s.split(":")[-1]
    try:
        return int(last)
    except ValueError:
        return None


def _find_entry_service(compose: dict) -> tuple[str, int]:
    """Return (service_name, internal_port) for the service that publishes a port.
    If several publish, prefer the first in file order. Falls back to ('', 80)."""
    services = compose.get("services") or {}
    for name, spec in services.items():
        if not isinstance(spec, dict):
            continue
        ports = spec.get("ports")
        if not ports:
            continue
        for entry in ports:
            port = _internal_port(entry)
            if port is not None:
                return name, port
    return "", 80


def load_benchmark(bench_dir: Path) -> Benchmark | None:
    meta_path = bench_dir / "benchmark.json"
    if not meta_path.is_file():
        return None
    try:
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None

    entry_service, entry_port = "", 80
    for compose_name in ("docker-compose.yml", "docker-compose.yaml"):
        compose_path = bench_dir / compose_name
        if compose_path.is_file():
            try:
                compose = yaml.safe_load(compose_path.read_text(encoding="utf-8")) or {}
                entry_service, entry_port = _find_entry_service(compose)
            except (yaml.YAMLError, OSError):
                pass
            break

    return Benchmark(
        id=bench_dir.name,
        dir=bench_dir,
        name=meta.get("name", bench_dir.name),
        description=meta.get("description", ""),
        level=str(meta.get("level", "")),
        tags=list(meta.get("tags", [])),
        win_condition=meta.get("win_condition", "flag"),
        entry_service=entry_service,
        entry_port=entry_port,
    )


def load_catalog(benchmarks_dir: Path) -> list[Benchmark]:
    """Load every benchmark under benchmarks_dir, sorted by id."""
    out = []
    for child in sorted(Path(benchmarks_dir).iterdir()):
        if child.is_dir():
            bench = load_benchmark(child)
            if bench is not None:
                out.append(bench)
    return out
