# Skidc × XBOW Validation Benchmarks

Automated benchmarking of Skidc against the [XBOW Validation Benchmarks](https://github.com/xbow-engineering/validation-benchmarks)
— 104 CTF-style web challenges, each hiding a `FLAG{...}`. The harness builds each
challenge, points a fresh Skidc project at it, waits for the agent to capture the flag,
verifies it against the deterministic ground-truth flag, and produces a Markdown report.

## How it works

```
 host (or compose stack)                          docker network: skidc-bench
 ┌──────────────┐  ┌──────────────┐               ┌──────────────────────────┐
 │ skidc-server │◄─┤ skidc-       │  docker exec  │ skidc-dispatch-proj_NNN   │
 │   :8000      │  │ dispatcher   │──────────────►│ (Kali worker + agent)     │
 └──────▲───────┘  └──────────────┘               └─────────────┬────────────┘
        │                                                        │ http://xben-001-24:80
        │ create project / poll                  ┌───────────────▼────────────┐
 ┌──────┴────────────┐                           │ benchmark web container     │
 │ benchmark_runner  │── docker compose build/up │ (attached to skidc-bench    │
 │  (this harness)   │── docker network connect  │  with alias = benchmark id) │
 └───────────────────┘                           └─────────────────────────────┘
```

Key design choices (and why they differ from a naive plan):

- **Flag = `FLAG{ sha256(UPPERCASE(id)) }`, lowercase hex.** Matches the benchmarks'
  `common.mk` exactly. (`sha256(name).upper()` is wrong — it uppercases the digest.)
  The `.env` flag in each benchmark is a decoy overridden at build time.
- **Shared docker network instead of host networking.** Workers never call the Skidc
  API (the dispatcher is the only protocol writer), so a worker only needs to reach the
  *target*. Putting both on `skidc-bench` lets the worker hit `http://<benchmark-id>:80`
  by DNS — deterministic, and identical on Linux and Docker Desktop/Windows. No random
  published-port discovery.
- **Ground-truth verification.** A run counts as solved only when the exact `FLAG{...}`
  appears in a fact. "Project completed" (agent self-declared) is reported separately.
- **Pure stdlib + the docker CLI.** No `make`, no `docker-py`, no pip installs to run it.

## Prerequisites

- Docker + `docker compose` v2+ (you have v5.1.3 ✓)
- Built images:
  ```bash
  # from D:\skidc
  docker build -t skidc-app -f Dockerfile .
  docker build -t skidc-worker:latest -f container/Dockerfile container
  ```
- A DeepSeek (or other) API key in the dispatch config.
- The benchmarks checked out at `D:\validation-benchmarks`.

## Setup

1. **Create the shared network** (the runner also does this automatically, but the
   dispatcher needs it to exist when it starts):
   ```bash
   docker network create skidc-bench
   ```

2. **Configure the dispatcher.** Copy the template and add your key:
   ```bash
   cp benchmark/dispatch_bench.example.yaml dispatch.yaml
   # edit dispatch.yaml: set ANTHROPIC_AUTH_TOKEN
   ```
   The template already sets `container.network_mode: skidc-bench` — this is mandatory.

3. **Start Skidc.** Either option works; the runner only needs the server reachable.

   **A) Compose stack (recommended).** Attach the dispatcher to the shared network so
   it and its workers can resolve benchmark aliases. Easiest: run the stack, then
   `docker network connect skidc-bench skidc-dispatcher` is *not* needed — workers are
   created with `network_mode: skidc-bench` directly, so only the worker containers (not
   the dispatcher) need it. Start it:
   ```bash
   docker compose up -d --build
   ```

   **B) Host process.**
   ```bash
   cd skidc && uv run skidc serve --host 0.0.0.0 &
   cd skidc && uv run skidc dispatch --config ../dispatch.yaml &
   ```

## Run

Quick smoke test — one easy benchmark:
```bash
cd benchmark
python runner.py --benchmarks-dir D:\validation-benchmarks\benchmarks \
  --only XBEN-001-24 --timeout 1800
```

Representative sample — first 2 of each difficulty (6 total):
```bash
python runner.py --benchmarks-dir D:\validation-benchmarks\benchmarks \
  --sample 2 --max-concurrent 2
```

Focused — all XSS challenges:
```bash
python runner.py --benchmarks-dir D:\validation-benchmarks\benchmarks --tag xss
```

Full suite (long — see estimates below):
```bash
python runner.py --benchmarks-dir D:\validation-benchmarks\benchmarks \
  --max-concurrent 3 --timeout 1800
```

The runner is **resumable**: it skips benchmarks that already have a
`results/raw/<id>.json`. Add `--rerun` to force. Ctrl-C stops launching new ones;
in-flight benchmarks finish and are saved.

### Useful flags
| Flag | Meaning |
|---|---|
| `--only A,B` | run just these benchmark ids |
| `--level 1,2` | filter by difficulty |
| `--tag xss,idor` | filter by vuln tag |
| `--sample N` | first N per level (quick representative run) |
| `--limit N` | cap total after filters |
| `--max-concurrent N` | parallel benchmarks (keep ≤ dispatcher `max_running_projects`) |
| `--timeout S` | per-benchmark solve budget (default 1800s) |
| `--keep-failed` | leave non-captured targets up for manual inspection |
| `--rerun` | re-run even if a result exists |

## Report

```bash
python report.py --results-dir results/raw --output results/report.md
```
Produces overview (capture rate, timings), by-difficulty and by-tag tables, a
per-benchmark detail table, and a failure analysis section.

## Cleanup

```bash
# stop Skidc
docker compose down -v            # if using the stack
# the runner tears down each benchmark automatically; to sweep leftovers:
docker ps -a --filter "name=xben-" -q | xargs -r docker rm -f
docker network rm skidc-bench
```

## Estimates & cautions

- **Time:** ~10–60 min per benchmark. Full 104 at concurrency 3 ≈ 20–50 h.
- **Cost:** ~$1/benchmark on DeepSeek ⇒ ~$100–200 for the full suite.
- **Disk:** benchmark images total ~50–100 GB. Run in batches (`--tag` / `--level` /
  `--limit`) and let `completed_action: remove` + `compose down -v` reclaim space.
- **Concurrency:** `--max-concurrent` bounds how many benchmarks build/run at once, but
  the *dispatcher* decides how many projects it schedules (`max_running_projects`). Keep
  them aligned, and give workers enough `max_running` to actually work the projects.

## Files

| File | Role |
|---|---|
| `runner.py` | orchestrator (build → up → connect → project → poll → verify → teardown) |
| `report.py` | raw JSON → Markdown report |
| `flag.py` | deterministic flag computation + verification |
| `catalog.py` | parse benchmark.json + compose to find each target's entry service/port |
| `compose.py` | docker / docker compose CLI wrappers |
| `skidc_client.py` | stdlib Skidc API client (create/get/stop project) |
| `dispatch_bench.example.yaml` | dispatcher config template (network_mode: skidc-bench) |
| `results/raw/<id>.json` | per-benchmark result (gitignored) |
| `results/report.md` | generated report (gitignored) |
