"""Offline self-check for the benchmark harness — no Docker, no Skidc, no LLM needed.

Validates the pure-Python pieces against the real benchmark corpus on disk:
  - flag computation matches the spec for a spread of ids
  - the catalog parses all 104, with the documented level/tag distribution
  - every benchmark resolves an entry service + internal port
  - the report generator renders from synthetic results

Run:  python selfcheck.py --benchmarks-dir D:\\validation-benchmarks\\benchmarks
Exits non-zero on any failure.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import tempfile
from collections import Counter
from pathlib import Path

import report
from catalog import load_catalog
from flag import compute_flag, find_flag_in_facts

EXPECTED_LEVELS = {"1": 45, "2": 51, "3": 8}
EXPECTED_TAGS = {"xss": 23, "default_credentials": 18, "idor": 15,
                 "privilege_escalation": 14, "ssti": 13, "command_injection": 11}


def check(cond: bool, msg: str) -> None:
    if not cond:
        raise AssertionError(msg)
    print(f"  ok: {msg}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--benchmarks-dir", type=Path, required=True)
    args = ap.parse_args()

    print("1. flag computation")
    for bid in ["XBEN-001-24", "XBEN-050-24", "XBEN-104-24"]:
        want = "FLAG{" + hashlib.sha256(bid.upper().encode()).hexdigest() + "}"
        check(compute_flag(bid) == want, f"{bid} flag matches spec")
    check(find_flag_in_facts(
        [{"id": "f001", "description": "got it: " + compute_flag("XBEN-001-24")}],
        compute_flag("XBEN-001-24")) is not None, "flag found in fact text")

    print("2. catalog parse of the real corpus")
    cat = load_catalog(args.benchmarks_dir)
    check(len(cat) == 104, f"loaded 104 benchmarks (got {len(cat)})")
    levels = Counter(b.level for b in cat)
    for lvl, n in EXPECTED_LEVELS.items():
        check(levels.get(lvl) == n, f"level {lvl} count == {n} (got {levels.get(lvl)})")
    tags = Counter(t for b in cat for t in b.tags)
    for tag, n in EXPECTED_TAGS.items():
        check(tags.get(tag) == n, f"tag {tag} count == {n} (got {tags.get(tag)})")
    no_entry = [b.id for b in cat if not b.entry_service]
    check(not no_entry, f"every benchmark has an entry service (missing: {no_entry})")
    check(all(b.entry_port > 0 for b in cat), "every benchmark has a positive entry port")

    print("3. report generation from synthetic results")
    samples = [
        {"id": "XBEN-001-24", "name": "IDOR", "level": "2", "tags": ["idor"], "status": "captured",
         "flag_captured": True, "project_completed": True, "fact_count": 4, "intent_count": 3,
         "duration_s": 600.0, "error": None},
        {"id": "XBEN-009-24", "name": "Broken", "level": "1", "tags": ["xss"], "status": "up_failed",
         "flag_captured": False, "project_completed": False, "fact_count": 0, "intent_count": 0,
         "duration_s": 30.0, "error": "no space left on device"},
    ]
    d = Path(tempfile.mkdtemp()) / "raw"
    d.mkdir(parents=True)
    for s in samples:
        (d / f"{s['id']}.json").write_text(json.dumps(s), encoding="utf-8")
    md = report.build_report(report.load_results(d))
    check("Flags captured: **1**" in md, "report counts captures")
    check("Failure analysis" in md and "no space left" in md, "report includes failure analysis")

    print("\nALL SELF-CHECKS PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
