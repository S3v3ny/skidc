"""Thin subprocess wrappers around the `docker` / `docker compose` CLIs.

No docker-py dependency — the host Python may not have it, and the CLI is the most
portable interface. Every call shells out and raises ComposeError on failure with the
captured output, so the runner can record a clean per-benchmark error.

Lifecycle per benchmark (see runner.py):
    build(...)            -> docker compose build --build-arg FLAG=...
    up(...)               -> docker compose up -d --wait   (waits on healthchecks)
    entry_container(...)  -> docker compose ps --format json -> container id of entry svc
    connect_network(...)  -> docker network connect --alias <alias> <net> <container>
    down(...)             -> docker compose down -v --remove-orphans
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path


class ComposeError(RuntimeError):
    pass


def _run(
    args: list[str],
    *,
    cwd: Path | None = None,
    env: dict | None = None,
    timeout: int = 1800,
) -> subprocess.CompletedProcess:
    full_env = None
    if env is not None:
        import os

        full_env = {**os.environ, **env}
    return subprocess.run(
        args,
        cwd=str(cwd) if cwd else None,
        env=full_env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=timeout,
    )


def _check(
    args: list[str],
    *,
    cwd: Path | None = None,
    env: dict | None = None,
    timeout: int = 1800,
) -> str:
    proc = _run(args, cwd=cwd, env=env, timeout=timeout)
    if proc.returncode != 0:
        cmd = " ".join(args)
        raise ComposeError(
            f"`{cmd}` failed (exit {proc.returncode}):\n{proc.stdout}\n{proc.stderr}".strip()
        )
    return proc.stdout


# --- shared network ---------------------------------------------------------


def ensure_network(name: str) -> None:
    """Create the shared bridge network if absent (idempotent)."""
    existing = _check(["docker", "network", "ls", "--format", "{{.Name}}"]).split()
    if name not in existing:
        _check(["docker", "network", "create", name])


def remove_network(name: str) -> None:
    _run(["docker", "network", "rm", name])  # best-effort


# --- per-benchmark compose project -----------------------------------------


def _compose_base(bench_dir: Path, project: str) -> list[str]:
    # --project-directory keeps .env loading + relative build contexts correct.
    return ["docker", "compose", "--project-directory", str(bench_dir), "-p", project]


def build(
    bench_dir: Path,
    project: str,
    flag: str,
    *,
    no_cache: bool = False,
    timeout: int = 2400,
) -> str:
    """Build the benchmark images with the computed flag injected as a build arg.

    common.mk passes BOTH `FLAG` and `flag` (some Dockerfiles read the lowercase one),
    so we mirror that. We also export them into the build env to override the decoy
    value in the benchmark's .env."""
    args = _compose_base(bench_dir, project) + [
        "build",
        "--build-arg",
        f"FLAG={flag}",
        "--build-arg",
        f"flag={flag}",
    ]
    if no_cache:
        args.append("--no-cache")
    return _check(
        args, cwd=bench_dir, env={"FLAG": flag, "flag": flag}, timeout=timeout
    )


def up(bench_dir: Path, project: str, flag: str, *, timeout: int = 600) -> str:
    """Start the project detached and wait for healthchecks (--wait)."""
    args = _compose_base(bench_dir, project) + ["up", "-d", "--wait"]
    return _check(
        args, cwd=bench_dir, env={"FLAG": flag, "flag": flag}, timeout=timeout
    )


def _parse_ps(stdout: str) -> list[dict]:
    """docker compose ps --format json emits either a JSON array (newer) or one JSON
    object per line (older). Handle both."""
    stdout = stdout.strip()
    if not stdout:
        return []
    try:
        data = json.loads(stdout)
        return data if isinstance(data, list) else [data]
    except json.JSONDecodeError:
        out = []
        for line in stdout.splitlines():
            line = line.strip()
            if line:
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
        return out


def entry_container(bench_dir: Path, project: str, service: str) -> str:
    """Return the container id (or name) of the entry service after `up`."""
    stdout = _check(
        _compose_base(bench_dir, project) + ["ps", "--format", "json"], cwd=bench_dir
    )
    rows = _parse_ps(stdout)
    # Match the compose 'Service' field; fall back to the only running container.
    for row in rows:
        if row.get("Service") == service:
            return row.get("ID") or row.get("Name") or ""
    if len(rows) == 1:
        return rows[0].get("ID") or rows[0].get("Name") or ""
    # Last resort: any row whose Name/Service contains the service token.
    for row in rows:
        if service and service in (row.get("Name", "") + row.get("Service", "")):
            return row.get("ID") or row.get("Name") or ""
    raise ComposeError(
        f"could not find entry container for service '{service}' in project '{project}'; ps rows={rows}"
    )


def connect_network(network: str, container: str, alias: str) -> None:
    """Attach a running container to the shared network under a stable DNS alias.
    Idempotent-ish: a repeat connect errors, which we swallow."""
    proc = _run(["docker", "network", "connect", "--alias", alias, network, container])
    if proc.returncode != 0 and "already exists" not in (proc.stderr + proc.stdout):
        raise ComposeError(f"network connect failed: {proc.stderr or proc.stdout}")


def down(bench_dir: Path, project: str, *, remove_images: bool = False) -> None:
    """Tear down the project. Volumes always removed; images optionally."""
    args = _compose_base(bench_dir, project) + ["down", "-v", "--remove-orphans"]
    if remove_images:
        args += ["--rmi", "local"]
    _run(args, cwd=bench_dir, timeout=300)  # best-effort cleanup
