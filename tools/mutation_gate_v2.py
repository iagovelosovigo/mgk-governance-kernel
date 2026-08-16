#!/usr/bin/env python3
"""Mutation Gate v2 — machine-readable gate over per-mutant classification.

Reads a mutmut per-mutant results dump and the per-mutant classification,
computes EVALUABLE = KILLED + SURVIVED_KILLABLE and
MUTATION_SCORE_V2 = KILLED / EVALUABLE, and emits a FAIL_CLOSED verdict when
any INDETERMINATE mutant remains or the score is below 0.90.

Per MGK-MUTATION-GATE-V2.yaml. Preserves the v1 gate and its historical FAIL.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

CATEGORIES = ("KILLED", "SURVIVED_KILLABLE", "EQUIVALENT_PROVEN", "INVALID_MUTANT", "UNREACHABLE_PROVEN", "INDETERMINATE")


def parse_results(results_text: str) -> dict[str, str]:
    status: dict[str, str] = {}
    for line in results_text.splitlines():
        m = re.match(r"\s+(\S+): (killed|survived|timeout|no tests|suspicious)", line)
        if m:
            status[m.group(1)] = m.group(2)
    return status


def load_classification(path: Path) -> list[dict]:
    data = json.loads(path.read_text())
    return data["mutants"]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--results", type=Path, required=True, help="mutmut per-mutant results dump")
    parser.add_argument("--classification", type=Path, required=True, help="mutation-v2-classification.json")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()

    results = parse_results(args.results.read_text())
    classified = load_classification(args.classification)
    classified_by_id = {r["id"]: r for r in classified}

    missing = [mid for mid in results if mid not in classified_by_id]
    extra = [r["id"] for r in classified if r["id"] not in results]

    counts = {c: 0 for c in CATEGORIES}
    record = {}
    for mid, run_status in results.items():
        rec = classified_by_id.get(mid)
        if rec is None:
            record[mid] = {"run_status": run_status, "classification": "INDETERMINATE", "reason": "missing classification record"}
            counts["INDETERMINATE"] += 1
            continue
        cat = rec["classification"]
        if cat not in CATEGORIES:
            cat = "INDETERMINATE"
        counts[cat] += 1
        record[mid] = {"run_status": run_status, "classification": cat}

    for mid, rec in classified_by_id.items():
        if mid not in record:
            record[mid] = {"run_status": "not in results", "classification": rec["classification"]}

    killed = counts["KILLED"]
    survived_killable = counts["SURVIVED_KILLABLE"]
    evaluable = killed + survived_killable
    score = killed / evaluable if evaluable else 0.0
    indeterminate = counts["INDETERMINATE"]

    verdict = "PASS" if (score >= 0.90 and indeterminate == 0 and evaluable > 0) else "FAIL"
    if indeterminate > 0:
        verdict = "FAIL_CLOSED"

    report = {
        "schema_version": "mgk.mutation-gate.v2",
        "contract_id": "MGK-v0.1.0-mutation-gate-2",
        "counts": counts,
        "EVALUABLE": evaluable,
        "MUTATION_SCORE_V2": round(score, 6),
        "threshold": 0.90,
        "INDETERMINATE_COUNT": indeterminate,
        "verdict": verdict,
        "unclassified_in_results": missing,
        "classified_not_in_results": extra,
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if verdict == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())