"""Skidc × XBOW benchmark orchestrator.

For each selected benchmark, in its own worker thread:
  1. compute the deterministic flag
  2. `docker compose build` it with that flag injected
  3. `docker compose up -d --wait`
  4. attach its web container to the shared `skidc-bench` network under a DNS alias
  5. create a Skidc project whose origin is `http://<alias>:<port>`
  6. poll the project until the flag appears in a fact / it completes / it times out
  7. verify the flag, write a raw JSON result, tear the benchmark down

Small-batch parallelism via a thread pool (`--max-concurrent`). Each thread runs one
benchmark's full lifecycle serially; the pool bounds how many run at once. Note the
Skidc dispatcher has its OWN `max_running_projects` cap — keep `--max-concurrent` <= it
so created projects actually get scheduled (see README).

Resumable: a benchmark whose `results/raw/<id>.json` already exists is skipped unless
`--rerun`. Ctrl-C stops launching new benchmarks; in-flight ones finish and are saved.

Run-plane assumption: the Skidc server + dispatcher are already up (host `uv run` or the
compose stack) and the dispatcher's `container.network_mode` is `skidc-bench`. The runner
does NOT start Skidc — it only manages benchmarks + projects.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

import compose
from catalog import Benchmark, load_catalog
from flag import compute_flag, find_flag_in_facts
from skidc_client import SkidcClient, SkidcError

NETWORK = "skidc-bench"
_print_lock = threading.Lock()


def log(msg: str) -> None:
    with _print_lock:
        print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}", flush=True)


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _project_name(bench_id: str) -> str:
    # docker compose project names must be lowercase + [a-z0-9_-]
    return bench_id.lower()


def run_one(
    bench: Benchmark,
    client: SkidcClient,
    raw_dir: Path,
    *,
    timeout: int,
    poll_interval: int,
    build_timeout: int,
    keep_failed: bool,
) -> dict:
    """Run a single benchmark end to end and return its result dict (also written to disk)."""
    project = _project_name(bench.id)
    expected_flag = compute_flag(bench.id)
    result: dict = {
        "id": bench.id,
        "name": bench.name,
        "level": bench.level,
        "tags": bench.tags,
        "target_url": bench.target_url,
        "expected_flag": expected_flag,
        "status": "error",
        "flag_captured": False,
        "project_completed": False,
        "project_id": None,
        "capturing_fact_id": None,
        "fact_count": 0,
        "intent_count": 0,
        "started_at": _now_iso(),
        "ended_at": None,
        "duration_s": 0,
        "error": None,
    }
    started = time.monotonic()

    def finish(status: str, error: str | None = None) -> dict:
        result["status"] = status
        result["error"] = error
        result["ended_at"] = _now_iso()
        result["duration_s"] = round(time.monotonic() - started, 1)
        (raw_dir / f"{bench.id}.json").write_text(
            json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        return result

    # 1-3. build + up
    try:
        log(f"{bench.id}: building ...")
        compose.build(bench.dir, project, expected_flag, timeout=build_timeout)
        log(f"{bench.id}: up --wait ...")
        compose.up(bench.dir, project, expected_flag, timeout=600)
    except compose.ComposeError as exc:
        log(f"{bench.id}: build/up FAILED")
        return finish("up_failed", str(exc)[:4000])
    except subprocess.TimeoutExpired as exc:
        return finish("up_failed", f"docker timeout: {exc}")

    try:
        # 4. attach web container to the shared network
        try:
            container = compose.entry_container(bench.dir, project, bench.entry_service)
            compose.connect_network(NETWORK, container, bench.alias)
            log(f"{bench.id}: target at {bench.target_url}")
        except compose.ComposeError as exc:
            return finish("network_failed", str(exc)[:4000])

        # 5. create skidc project
        hints = [{
            "creator": "benchmark",
            "content": (
                f"Challenge: {bench.name}. {bench.description} "
                f"Vulnerability hint tags: {', '.join(bench.tags) or 'n/a'}. "
                f"The flag is in the format FLAG{{...}}. Capture it and report it verbatim in a fact."
            ),
        }]
        try:
            detail = client.create_project(
                title=f"XBOW {bench.id}",
                origin=f"Authorized CTF web target at {bench.target_url} (level {bench.level}).",
                goal="Find the hidden flag (format FLAG{...}) and report it verbatim.",
                hints=hints,
            )
        except SkidcError as exc:
            return finish("error", f"create_project: {exc}")
        project_id = detail["project"]["id"]
        result["project_id"] = project_id
        log(f"{bench.id}: project {project_id} created, polling ...")

        # 6-7. poll until flag / completed / timeout
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            time.sleep(poll_interval)
            try:
                d = client.get_project(project_id)
            except SkidcError:
                continue
            facts = d.get("facts", [])
            result["fact_count"] = len([f for f in facts if f["id"] not in ("origin", "goal")])
            result["intent_count"] = len(d.get("intents", []))
            status = d.get("project", {}).get("status")
            hit = find_flag_in_facts(facts, expected_flag)
            if hit is not None:
                result["flag_captured"] = True
                result["capturing_fact_id"] = hit["id"]
                result["project_completed"] = status == "completed"
                log(f"{bench.id}: FLAG CAPTURED in {hit['id']} ({result['duration_s']}s)")
                return finish("captured")
            if status == "completed":
                # agent declared completion but flag not in a fact — record for review
                result["project_completed"] = True
                log(f"{bench.id}: project completed but flag NOT found in facts")
                return finish("completed_no_flag")
            if status == "stopped":
                return finish("stopped")
        log(f"{bench.id}: TIMEOUT after {timeout}s")
        return finish("timeout")
    finally:
        # 9. teardown — keep failed targets up for inspection if requested
        if keep_failed and result["status"] not in ("captured",):
            log(f"{bench.id}: leaving containers up (--keep-failed)")
        else:
            compose.down(bench.dir, project)


def select_benchmarks(cat: list[Benchmark], args) -> list[Benchmark]:
    out = cat
    if args.only:
        wanted = {x.strip().upper() for x in args.only.split(",") if x.strip()}
        out = [b for b in out if b.id.upper() in wanted]
    if args.level:
        levels = {x.strip() for x in args.level.split(",")}
        out = [b for b in out if b.level in levels]
    if args.tag:
        tags = {x.strip().lower() for x in args.tag.split(",")}
        out = [b for b in out if tags & {t.lower() for t in b.tags}]
    if args.sample:
        # take the first N per level for a quick representative run
        by_level: dict[str, list[Benchmark]] = {}
        for b in out:
            by_level.setdefault(b.level, []).append(b)
        sampled = []
        for level in sorted(by_level):
            sampled.extend(by_level[level][: args.sample])
        out = sampled
    if args.limit:
        out = out[: args.limit]
    return out


def main() -> int:
    p = argparse.ArgumentParser(description="Run Skidc against the XBOW Validation Benchmarks")
    p.add_argument("--benchmarks-dir", required=True, type=Path)
    p.add_argument("--skidc-url", default="http://127.0.0.1:8000")
    p.add_argument("--output-dir", type=Path, default=Path(__file__).parent / "results")
    p.add_argument("--max-concurrent", type=int, default=2,
                   help="benchmarks run in parallel; keep <= dispatcher max_running_projects")
    p.add_argument("--timeout", type=int, default=1800, help="per-benchmark solve timeout (s)")
    p.add_argument("--build-timeout", type=int, default=2400, help="per-benchmark docker build timeout (s)")
    p.add_argument("--poll-interval", type=int, default=10, help="project poll interval (s)")
    p.add_argument("--only", help="comma list of benchmark ids, e.g. XBEN-001-24,XBEN-050-24")
    p.add_argument("--level", help="comma list of levels to include, e.g. 1,2")
    p.add_argument("--tag", help="comma list of vuln tags to include, e.g. xss,idor")
    p.add_argument("--sample", type=int, help="take first N per level (quick representative run)")
    p.add_argument("--limit", type=int, help="cap total benchmarks after other filters")
    p.add_argument("--rerun", action="store_true", help="re-run benchmarks even if a result exists")
    p.add_argument("--keep-failed", action="store_true", help="leave non-captured targets up for inspection")
    args = p.parse_args()

    raw_dir = args.output_dir / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)

    client = SkidcClient(args.skidc_url)
    if not client.health():
        print(f"ERROR: Skidc server not reachable at {args.skidc_url}. Start it first.", file=sys.stderr)
        return 1

    cat = load_catalog(args.benchmarks_dir)
    if not cat:
        print(f"ERROR: no benchmarks under {args.benchmarks_dir}", file=sys.stderr)
        return 1
    selected = select_benchmarks(cat, args)

    if not args.rerun:
        before = len(selected)
        selected = [b for b in selected if not (raw_dir / f"{b.id}.json").exists()]
        skipped = before - len(selected)
        if skipped:
            log(f"resuming: skipping {skipped} already-done benchmark(s)")

    if not selected:
        log("nothing to run (all selected benchmarks already have results; use --rerun to force)")
        return 0

    log(f"running {len(selected)} benchmark(s), {args.max_concurrent} at a time, "
        f"timeout {args.timeout}s each")
    compose.ensure_network(NETWORK)

    done = 0
    captured = 0
    try:
        with ThreadPoolExecutor(max_workers=args.max_concurrent) as pool:
            futures = {
                pool.submit(
                    run_one, b, client, raw_dir,
                    timeout=args.timeout, poll_interval=args.poll_interval,
                    build_timeout=args.build_timeout, keep_failed=args.keep_failed,
                ): b
                for b in selected
            }
            for fut in as_completed(futures):
                b = futures[fut]
                try:
                    res = fut.result()
                    done += 1
                    if res["flag_captured"]:
                        captured += 1
                    log(f"PROGRESS {done}/{len(selected)} — {b.id}: {res['status']} "
                        f"(captured so far: {captured})")
                except Exception as exc:  # noqa: BLE001 — never let one benchmark kill the run
                    log(f"{b.id}: unhandled error {exc}")
    except KeyboardInterrupt:
        log("interrupted — in-flight benchmarks finishing; rerun to resume the rest")

    log(f"DONE: {done} run, {captured} flag(s) captured. Raw results in {raw_dir}")
    log("Generate the report with: python report.py --results-dir results/raw --output results/report.md")
    return 0


if __name__ == "__main__":
    sys.exit(main())
