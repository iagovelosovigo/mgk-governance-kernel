#!/usr/bin/env python3
"""Run mutmut and emit a machine-readable mutation observation."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import subprocess


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--candidate-root", type=Path, required=True)
    parser.add_argument("--tests", type=Path, default=Path(__file__).resolve().parents[1] / "tests")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    run = subprocess.run(
        ["mutmut", "run", "--paths-to-mutate", "src"],
        cwd=args.candidate_root,
        text=True,
        capture_output=True,
        timeout=1800,
    )
    summary = subprocess.run(
        ["mutmut", "results"],
        cwd=args.candidate_root,
        text=True,
        capture_output=True,
        timeout=120,
    )
    text = summary.stdout + summary.stderr
    counts = {name: int(value) for name, value in re.findall(r"(killed|survived|timeout|suspicious|skipped)\s*[:=]\s*(\d+)", text, re.I)}
    killed = counts.get("killed", 0)
    survived = counts.get("survived", 0)
    denominator = killed + survived
    score = 100.0 * killed / denominator if denominator else 0.0
    report = {
        "schema_version": "mgk.mutation.v1",
        "status": "PASS" if run.returncode == 0 and denominator and score >= 90.0 else "FAIL",
        "score_percent": score,
        "counts": counts,
        "runner_exit_code": run.returncode,
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(report["status"])
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())

