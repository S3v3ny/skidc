<div align="center">

**[🇨🇳 中文](README.zh-CN.md)** | **[🇬🇧 English](README.md)**

# PentestMesh

### Multi-Agent Automated Penetration Testing Platform

*Define an **origin** and a **goal**. PentestMesh orchestrates LLM-powered agents*
*to autonomously plan, execute, and verify penetration testing workflows —*
*across Web, API, and Android targets.*

</div>

---

> **Naming note:** PentestMesh is the public project name. The internal Python package and CLI still use `skidc` temporarily for backward compatibility.

## What is PentestMesh?

PentestMesh is an automated penetration testing platform that uses multiple LLM-powered agents
to drive the full pentest lifecycle — from reconnaissance through exploitation — without
manual step-by-step scripting.

You describe **where you start** (a target IP, URL, APK, or domain) and **what success
looks like** (get a shell, capture the flag, find an IDOR). PentestMesh's dispatcher breaks the
problem into parallel exploration tasks, runs them inside isolated Docker containers, and
writes every confirmed finding back to a shared task graph that drives the next round of
reasoning.

### Core capabilities

| Capability | Description |
|------------|-------------|
| **Phased pentest with gate control** | RECON → Explore phase transition is driven by the project's `recon_profile`, so domain, IP, API, Android, and mixed targets can use different required evidence |
| **Android MCP Bridge** | 18 HTTP endpoints for mobile app control — UI interaction, screenshot, network capture — seamlessly integrated into the pentest workflow |
| **Fact–intent task graph** | Every confirmed finding (fact) and exploration direction (intent) is tracked, visualized, and used to drive the next reasoning cycle |
| **Attack path annotation** | Exploitation chains are automatically identified with severity assessment (critical / high / medium / low) |
| **Pluggable LLM backends** | Swap between DeepSeek, Qwen, Claude, or any compatible model — agent CLI and LLM are fully decoupled |
| **Two-phase conclude** | Timeouts don't lose work — the same agent session is resumed to harvest partial results |

---

## How it works

### Architecture

```
              ┌────────────────────────────────────┐
              │           PentestMesh Server             │   truth source:
              │   Facts + Intents + Hints + Paths  │   graph consistency only
              └─────────────────┬──────────────────┘
                                │  read / write protocol API
              ┌─────────────────┴──────────────────┐
              │             Dispatcher             │   sole protocol writer:
              │  schedule → claim lease → run →    │   leases, heartbeats, timeouts,
              │  parse → write back → cleanup      │   container lifecycle
              └──────────┬───────────────┬─────────┘
                         │               │
              ┌──────────┴─────┐  ┌──────┴───────────┐   one container per project;
              │ Worker (proj A)│  │ Worker (proj B)  │   agents exec inside it,
              │  claude→DeepSeek│  │  codex→Qwen      │   coordinate via the graph only
              └─────────────────┘  └──────────────────┘
```

**Server** (FastAPI + SQLite) keeps the task graph consistent and owns the intent-claim /
reason-lease state machine. **Dispatcher** is the only component that writes to the
protocol: it reads the graph, decides the task type per project, claims a lease, runs the
worker in that project's container, parses the structured JSON result, and writes it back.

### Three task types

All tasks are executed by the same universal worker inside a Docker container:

| Task | Trigger | What it does | Output |
|------|---------|-------------|--------|
| **Bootstrap** | Project is in its initial state | Try to solve the whole problem directly | Fact + possible Complete |
| **Reason** | New facts appeared, or no open intents | Read the full graph: goal met? what to explore next? | Complete / new Intents / no-op |
| **Explore** | An unclaimed open intent exists | Claim one intent, execute it, report findings | One Fact |

Both `bootstrap` and `explore` are **two-phase**: if the main attempt times out or returns
unparseable output, the dispatcher resumes the *same agent session* with a `conclude`
prompt — "stop working, just summarize what you confirmed" — so partial progress is
preserved instead of being thrown away.

### Phased pentest with RECON gate

When a project starts in `recon` phase (real-website mode), the dispatcher enforces a
profile-aware **gate check** before allowing the workflow to proceed to exploitation:

| RECON Category | Evidence Required |
|----------------|-------------------|
| Port scan | nmap / naabu results with open ports and services |
| Subdomain | subfinder / amass / DNS enumeration results |
| Directory | ffuf / gobuster / dirsearch path discovery |
| Asset | katana / crawler results with URLs and JS files |

Only the categories listed in the project's `recon_profile.required_categories` must be
covered before the system transitions from `recon` to `explore`. For example, a single-IP
assessment can disable subdomain enumeration, while an Android assessment can require
`android_app`, `android_ui`, and `mobile_api` instead of web categories. When the gate
passes, potential sub-targets (subdomains, open services, interesting paths) are extracted
and written to the graph as new facts without duplicating them after dispatcher restarts.

---

## The model is not hard-coded

A worker's **`type`** selects the *agent CLI loop*; the worker's **`env`** selects the
*actual LLM* behind it. They are decoupled, so you mix and match freely:

| Worker `type` | Agent CLI it drives | Endpoint it talks to (set via env) | Example model |
|---------------|---------------------|------------------------------------|---------------|
| `claudecode`  | `claude`            | `ANTHROPIC_BASE_URL` (Anthropic-compatible) | **DeepSeek** (`https://api.deepseek.com/anthropic`) |
| `codex`       | `codex`             | `CODEX_BASE_URL` (OpenAI/Responses-compatible) | **Qwen** (`https://dashscope.aliyuncs.com/compatible-mode/v1`) |
| `mock`        | a local script      | none — deterministic outcomes for testing | — |

```yaml
# Run DeepSeek through the Claude Code agent loop:
- name: "claudecode_deepseek"
  type: "claudecode"
  env:
    ANTHROPIC_MODEL: "deepseek-v4-flash"
    ANTHROPIC_BASE_URL: "https://api.deepseek.com/anthropic"
    ANTHROPIC_AUTH_TOKEN: "<YOUR_ANTHROPIC_AUTH_TOKEN>"

# Run Qwen through the Codex agent loop:
- name: "codex_qwen"
  type: "codex"
  env:
    CODEX_MODEL: "qwen3.7-plus"
    CODEX_BASE_URL: "https://dashscope.aliyuncs.com/compatible-mode/v1"
    OPENAI_API_KEY: "<YOUR_OPENAI_API_KEY>"
```

Swapping models is a config edit. Adding a new backend is one new driver file in
`workers/adapters/`.

---

## Android MCP Bridge

PentestMesh includes a built-in Android control bridge for mobile application security testing.
It is a lightweight FastAPI service that wraps ADB commands into HTTP endpoints, allowing
pentest agents to interact with Android emulators or physical devices.

### Starting the bridge

```powershell
cd skidc
uv run skidc android-mcp --device-id emulator-5554 --host 127.0.0.1 --port 8765
```

### Endpoint overview

| Area | Endpoints |
|------|-----------|
| Device status | `GET /health`, `GET /devices` |
| App lifecycle | `POST /app/install`, `/app/start`, `/app/stop`, `/app/clear` |
| Input control | `POST /input/tap`, `/input/text`, `/input/swipe`, `/input/back`, `/input/home`, `/input/key` |
| Observation | `GET /observe/ui`, `/observe/activity`, `/observe/screenshot`, `POST /observe/logcat` |
| Network capture | `GET /network/history`, `POST /network/events`, `DELETE /network/history` |

### Configuring for Android targets

Use `dispatch_android.example.yaml` with two key settings:

```yaml
runtime:
  prompt_group: "android"

common_env:
  ANDROID_MCP_URL: "http://127.0.0.1:8765"
```

When creating a project, describe the Android target in `origin`:

```
APK: D:\targets\demo.apk
Package: com.example.demo
Device: emulator-5554
Test accounts: user_a / user_b
```

The Android prompt group guides workers to use the bridge during `explore` tasks and
report structured findings:

```json
{
  "description": "After logging in as user_a, order detail API /api/order/detail?order_id=1001 returns full order data without ownership check",
  "scope": "mobile_api",
  "vuln_type": "idor",
  "severity": "high"
}
```

See [ANDROID_MCP.md](ANDROID_MCP.md) for the full bridge documentation.

---

## Project layout

```
skidc\
├─ skidc\                         # the Python package (uv project)
│  ├─ src\skidc\
│  │  ├─ server\                  # FastAPI + SQLite task graph
│  │  │  ├─ db.py  models.py  services.py  app.py
│  │  │  ├─ routers\             # projects, intents, hints, settings, export
│  │  │  └─ static\index.html    # live graph dashboard (zero-dependency)
│  │  ├─ dispatcher\
│  │  │  ├─ config.py            # dispatch.yaml schema + model-swap env wiring
│  │  │  ├─ contracts.py         # strict JSON output validation
│  │  │  ├─ scheduler\loop.py    # the control plane / decision tree
│  │  │  ├─ tasks\               # bootstrap / reason / explore (+ conclude)
│  │  │  ├─ workers\             # driver abstraction
│  │  │  │  └─ adapters\         #   claudecode, codex, mock
│  │  │  ├─ runtime\             # docker exec, heartbeat lease, cancellation
│  │  │  ├─ recon_extractor.py   # RECON gate check + sub-target extraction
│  │  │  └─ prompts\             # default\ (offensive) + android\ (mobile) + mock\
│  │  ├─ android_mcp\            # Android MCP Bridge (FastAPI + ADB)
│  │  └─ cli.py                  # `skidc serve` / `skidc dispatch` / `skidc android-mcp`
│  └─ tests\                     # run with no Docker and no LLM
├─ container\                    # Kali worker image (Dockerfile + AGENTS.md)
├─ benchmark\                    # XBOW benchmark harness
├─ dispatch.example.yaml         # Web/API pentest template
├─ dispatch_android.example.yaml # Android pentest template
├─ dispatch_mock.yaml            # mock-only setup for local testing
├─ Dockerfile                    # builds skidc-app (server + dispatcher image)
├─ docker-compose.yaml
├─ ANDROID_MCP.md                # Android Bridge usage guide
└─ README.md
```

---

## Getting started

### Prerequisites

- **OS**: Windows 10/11 (WSL2 backend), macOS, or Linux
- **Docker Desktop** >= 4.10 (uses WSL2 on Windows; bind mount `C:\` works)
- **Python >= 3.12** and [uv](https://docs.astral.sh/uv/) — only needed for `uv run skidc serve / dispatch`; **not needed if you only use Docker Compose**
- For Windows: at least **8 GB free on C:** (WSL2 stores Docker's ext4.vhdx there)

### Path A — Docker Compose (recommended; no Python needed)

```powershell
# 1. Build the worker image (Kali + claude-code + codex). ~5-15 min, ~4.6 GB.
docker build -t skidc-worker:latest -f container/Dockerfile container

# 2. Create your dispatcher config from the template, then fill in LLM keys.
copy dispatch.example.yaml dispatch.yaml
notepad dispatch.yaml                  # fill in ANTHROPIC_AUTH_TOKEN / OPENAI_API_KEY

# 3. Build the app image and start everything.
docker compose up -d --build
```

`dispatch.yaml` is ignored by git and is meant to stay local. If a real provider key was
ever committed or shared, rotate it in the provider console; replacing it with a placeholder
in this repository does not invalidate the old key.

`docker compose up -d --build` will:
- build `skidc-app` (the server + dispatcher image) from the root `Dockerfile`
- start `skidc-server` (port 8000) and `skidc-dispatcher`
- mount `datas/skidc/` to `/root/.local/share/skidc/` inside the server
  (this is where the SQLite db lives; survives restarts)

To verify:

```powershell
docker ps --filter "name=skidc" --format "table {{.Names}}\t{{.Status}}"
# Expect: skidc-server (healthy), skidc-dispatcher (Up)

curl http://127.0.0.1:8000/projects
# Expect: [] (empty project list)
```

Open http://127.0.0.1:8000 to see the dashboard.

### Path B — `uv` directly (development; bypasses Docker for the app, still uses Docker for workers)

```powershell
# terminal 1: start the server
cd skidc
uv sync
uv run skidc serve --host 0.0.0.0

# terminal 2: start the dispatcher
cp dispatch.example.yaml dispatch.yaml
notepad dispatch.yaml
cd skidc
uv run skidc dispatch --config ..\dispatch.yaml

# Validate only your worker LLM configs (one ping per worker) and exit:
uv run skidc dispatch --config ..\dispatch.yaml --startup-healthcheck-only
```

### Path C — Tests only (no Docker, no LLM)

```powershell
cd skidc
uv sync --group dev
uv run --group dev pytest
```

Drives the **entire pipeline** — server protocol, scheduler decision tree, all three
task types, the two-phase conclude fallback, and the model-swap drivers — in-process
using the `mock` worker.

---

## Daily use

### Start a project

1. Open http://127.0.0.1:8000 in a browser.
2. Click **New Project**, fill in:
   - **Origin**: target IP / URL / domain / APK path
   - **Goal**: success condition (e.g. `get the root shell`, `find IDOR vulnerabilities`)
   - **Hints** (optional): things you already know (open ports, banners, credentials)
3. Submit. The dispatcher picks a worker, spawns a container, and starts the pentest loop.

For real websites, define the safety boundary at project creation time. The UI exposes
these fields, and the same structure can be sent to the API:

```json
{
  "title": "authorized web assessment",
  "origin": "https://app.example.test",
  "goal": "find authorization flaws within the agreed scope",
  "mode": "real_website",
  "bootstrap_enabled": false,
  "scope_policy": {
    "allowed_targets": ["app.example.test", "api.example.test"],
    "blocked_targets": ["admin.example.test"],
    "allowed_ports": [80, 443],
    "blocked_ports": [22],
    "allowed_paths": ["/app/"],
    "blocked_paths": ["/private/"],
    "support_ports": [3306],
    "allow_subdomains": false,
    "allow_domain_scan": false,
    "rate_limits": {},
    "passive_only": false
  },
  "recon_profile": {
    "target_type": "domain",
    "required_categories": ["port_scan", "subdomain", "directory", "asset"],
    "optional_categories": [],
    "disabled_categories": []
  }
}
```

The dispatcher injects this policy into worker prompts and performs basic structured
intent checks before dispatch, so obvious out-of-scope targets, blocked ports, and
passive-only violations are skipped instead of being executed.

### Watch progress

| What you want to see | Where to look |
|----------------------|---------------|
| The fact/intent graph growing | Dashboard (auto-refreshes) |
| What the agent is currently running | `docker exec <worker-container> ps aux` |
| Why a task was cancelled | `docker logs skidc-dispatcher --tail 100` |
| Which LLM call failed | `docker logs skidc-dispatch-proj_xxx` |

### Stop the system

```powershell
# Graceful stop (data preserved)
docker compose down

# Force stop (loses in-flight tasks)
docker compose down -v
```

### Restart after shutdown

```powershell
docker compose up -d
```

No rebuild needed — images are cached. Dashboard is ready in ~10 seconds.

---

## Swap the LLM brain

The agent CLI loop and the LLM behind it are decoupled. To switch:

1. Edit `dispatch.yaml`. The `env:` block of each worker is the only place to touch.
2. Common swaps:

| Want | Worker `type` | Required env |
|------|---------------|--------------|
| DeepSeek (Claude Code loop) | `claudecode` | `ANTHROPIC_BASE_URL`, `ANTHROPIC_MODEL`, `ANTHROPIC_AUTH_TOKEN` |
| Qwen (Codex loop) | `codex` | `CODEX_BASE_URL`, `CODEX_MODEL`, `OPENAI_API_KEY` |
| Anthropic Claude (real) | `claudecode` | `ANTHROPIC_BASE_URL=https://api.anthropic.com`, `ANTHROPIC_MODEL=claude-sonnet-4-5`, `ANTHROPIC_AUTH_TOKEN=<YOUR_ANTHROPIC_AUTH_TOKEN>` |

3. Restart the dispatcher — no rebuild required:

```powershell
docker compose restart skidc-dispatcher
```

---

## Troubleshooting

### Worker container exits with code 137

Exit code 137 = SIGKILL = OOM killer. Fix: hard-cap the worker container's memory in
`dispatch.yaml`:

```yaml
container:
  image: "skidc-worker:latest"
  network_mode: "host"
  completed_action: "remove"
  mem_limit: "3g"
```

### `docker exec` fails with "cannot be used with root/sudo privileges"

Claude Code refuses `--dangerously-skip-permissions` when running as root. Confirm
`container/Dockerfile` contains:

```dockerfile
RUN useradd -m -s /bin/bash kali && \
    echo "kali ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers
USER kali
```

### ghcr.io times out / 404

Common in CN networks. Use a Docker Hub base image instead:

```dockerfile
FROM python:3.13-slim-bookworm
RUN pip install uv
```

### Kali apt mirror fails (403)

Replace `mirror.wane.kr` with `mirrors.aliyun.com` in `container/Dockerfile`.

---

## Responsible use

PentestMesh targets authorized penetration-testing / CTF / security-assessment environments.
Use it **only** where you have explicit permission to operate. Unauthorized security
testing may be illegal and harmful. You are solely responsible for how you use this project.

---

## Development credit

The Android portion of this project was completed by me.
