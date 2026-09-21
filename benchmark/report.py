"""Aggregate per-benchmark raw JSON results into a Markdown report.

Reads results/raw/*.json (written by runner.py) and produces a report with:
  - overview (capture rate, status breakdown, timings)
  - by-difficulty table
  - by-vuln-tag table
  - per-benchmark detail
  - failure analysis (everything not captured)

"Captured" = the expected FLAG{...} appeared verbatim in a fact — the ground truth.
This is reported separately from "project_completed" (the agent's self-declared done),
so you can see cases where the agent declared victory without actually finding the flag.
"""
from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path

CAPTURED = "captured"


def load_results(raw_dir: Path) -> list[dict]:
    out = []
    for f in sorted(raw_dir.glob("*.json")):
        try:
            out.append(json.loads(f.read_text(encoding="utf-8")))
        except (json.JSONDecodeError, OSError):
            pass
    return out


def _rate(captured: int, total: int) -> str:
    return f"{(100 * captured / total):.0f}%" if total else "—"


def _avg_min(durations: list[float]) -> str:
    return f"{(sum(durations) / len(durations) / 60):.1f}" if durations else "—"


def _group_table(results: list[dict], key_fn, header: str, order=None) -> str:
    groups: dict[str, list[dict]] = defaultdict(list)
    for r in results:
        for k in key_fn(r):
            groups[k].append(r)
    keys = order or sorted(groups)
    lines = [f"| {header} | Total | Captured | Capture rate | Avg time (min) |",
             "|---|---|---|---|---|"]
    for k in keys:
        rows = groups.get(k, [])
        if not rows:
            continue
        cap = sum(1 for r in rows if r["status"] == CAPTURED)
        durs = [r["duration_s"] for r in rows if r["status"] == CAPTURED and r.get("duration_s")]
        lines.append(f"| {k} | {len(rows)} | {cap} | {_rate(cap, len(rows))} | {_avg_min(durs)} |")
    return "\n".join(lines)


STATUS_ICON = {
    "captured": "✅ captured",
    "completed_no_flag": "⚠️ completed (no flag in facts)",
    "timeout": "⏰ timeout",
    "up_failed": "🔧 build/up failed",
    "network_failed": "🔌 network failed",
    "stopped": "⏹ stopped",
    "error": "❌ error",
    "skipped": "⏭ skipped",
}


def build_report(results: list[dict]) -> str:
    total = len(results)
    captured = sum(1 for r in results if r["status"] == CAPTURED)
    status_counts: dict[str, int] = defaultdict(int)
    for r in results:
        status_counts[r["status"]] += 1
    cap_durs = [r["duration_s"] for r in results if r["status"] == CAPTURED and r.get("duration_s")]

    L = []
    L.append("# Skidc × XBOW Validation Benchmarks — Report\n")
    L.append("## Overview\n")
    L.append(f"- Benchmarks run: **{total}**")
    L.append(f"- Flags captured: **{captured}** ({_rate(captured, total)})")
    L.append(f"- Avg time to capture: **{_avg_min(cap_durs)} min**" if cap_durs else "- Avg time to capture: —")
    if cap_durs:
        fastest = min((r for r in results if r["status"] == CAPTURED), key=lambda r: r["duration_s"])
        slowest = max((r for r in results if r["status"] == CAPTURED), key=lambda r: r["duration_s"])
        L.append(f"- Fastest capture: {fastest['id']} ({fastest['duration_s']/60:.1f} min)")
        L.append(f"- Slowest capture: {slowest['id']} ({slowest['duration_s']/60:.1f} min)")
    L.append("\n### Status breakdown\n")
    L.append("| Status | Count |\n|---|---|")
    for st, n in sorted(status_counts.items(), key=lambda kv: -kv[1]):
        L.append(f"| {STATUS_ICON.get(st, st)} | {n} |")

    L.append("\n## By difficulty\n")
    L.append(_group_table(results, lambda r: [f"Level {r.get('level','?')}"], "Difficulty",
                          order=["Level 1", "Level 2", "Level 3"]))

    L.append("\n## By vulnerability tag\n")
    L.append(_group_table(results, lambda r: r.get("tags") or ["(untagged)"], "Tag"))

    L.append("\n## Per-benchmark detail\n")
    L.append("| Benchmark | Level | Tags | Status | Time (min) | Facts | Intents | Flag verified |")
    L.append("|---|---|---|---|---|---|---|---|")
    for r in sorted(results, key=lambda r: r["id"]):
        t = f"{r['duration_s']/60:.1f}" if r.get("duration_s") else "—"
        verified = "✅" if r["flag_captured"] else ("⚠️ declared" if r.get("project_completed") else "—")
        L.append(f"| {r['id']} | {r.get('level','?')} | {', '.join(r.get('tags', []))} | "
                 f"{STATUS_ICON.get(r['status'], r['status'])} | {t} | {r.get('fact_count',0)} | "
                 f"{r.get('intent_count',0)} | {verified} |")

    failures = [r for r in results if r["status"] != CAPTURED]
    if failures:
        L.append("\n## Failure analysis\n")
        for r in sorted(failures, key=lambda r: r["id"]):
            L.append(f"### {r['id']} — {r.get('name','')}")
            L.append(f"- Status: {STATUS_ICON.get(r['status'], r['status'])}")
            L.append(f"- Level {r.get('level','?')}, tags: {', '.join(r.get('tags', [])) or 'n/a'}")
            L.append(f"- Facts: {r.get('fact_count',0)}, intents: {r.get('intent_count',0)}, "
                     f"project_completed: {r.get('project_completed')}")
            if r.get("error"):
                err = r["error"].strip().splitlines()
                tail = " ".join(err[-3:])[:500]
                L.append(f"- Error tail: `{tail}`")
            L.append("")

    return "\n".join(L) + "\n"


def main() -> int:
    p = argparse.ArgumentParser(description="Generate a Markdown report from benchmark raw results")
    p.add_argument("--results-dir", type=Path, default=Path(__file__).parent / "results" / "raw")
    p.add_argument("--output", type=Path, default=Path(__file__).parent / "results" / "report.md")
    args = p.parse_args()

    results = load_results(args.results_dir)
    if not results:
        print(f"No results found in {args.results_dir}")
        return 1
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(build_report(results), encoding="utf-8")
    cap = sum(1 for r in results if r["status"] == CAPTURED)
    print(f"Report written to {args.output} ({len(results)} results, {cap} captured)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
