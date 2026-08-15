#!/usr/bin/env python3
"""Compare two independent clean-install reports without opinionated PASS."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("report_a", type=Path)
    parser.add_argument("report_b", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    a = json.loads(args.report_a.read_text(encoding="utf-8"))
    b = json.loads(args.report_b.read_text(encoding="utf-8"))
    checks = {
        "independent_labels": a.get("label") == "A" and b.get("label") == "B",
        "both_clean_pass": a.get("status") == b.get("status") == "PASS",
        "source_sha256_match": a.get("source_sha256") == b.get("source_sha256") and bool(a.get("source_sha256")),
        "source_tree_match": a.get("source_tree_sha256") == b.get("source_tree_sha256") and bool(a.get("source_tree_sha256")),
        "wheel_sha256_match": a.get("wheel_sha256") == b.get("wheel_sha256") and bool(a.get("wheel_sha256")),
        "test_outcome_match": a.get("tests") == b.get("tests") and a.get("tests", {}).get("status") == "PASS",
        "h14_outcome_match": a.get("h14") == b.get("h14") and a.get("h14", {}).get("status") == "PASS",
    }
    report = {
        "schema_version": "mgk.reproducibility.v1",
        **checks,
        "status": "PASS" if all(checks.values()) else "FAIL",
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(report["status"])
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())

