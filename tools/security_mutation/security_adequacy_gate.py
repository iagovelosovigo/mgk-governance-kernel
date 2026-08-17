#!/usr/bin/env python3
"""Phase 5: machine-readable Security Mutation Adequacy gate.

Reads the local mutation-adequacy evidence and emits a deterministic
verdict object. The gate is considered PASS only when:

  GLOBAL_MUTATION_SCORE       >= 0.90
  UNRESOLVED_HIGH             == 0
  UNRESOLVED_CRITICAL         == 0
  SECURITY_SENSITIVE_INDETERMINATE == 0
  FINAL_CODE_REPRODUCIBLE_SECURITY_BYPASSES == 0
  SECURITY_MUTATION_ADEQUACY  == PASS

The full-population score comes from the FRESH Phase 8 run; until that run
exists the tool records the last authoritative population score and reports
GLOBAL_MUTATION_GATE=FAIL with the exact score, so the gap is explicit.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent
EVID = REPO / "evidence" / "v0.2.0" / "security-mutation-adequacy"

HIGH_CRITICAL = ("SECURITY_BYPASS", "PERMISSION_WEAKENING", "INTEGRITY_WEAKENING")
RESOLVED = ("KILLED", "EQUIVALENT_PROVEN", "TEST_GAP_ONLY", "AVAILABILITY_ONLY")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--population", type=Path, default=EVID / "population-experiment.json")
    parser.add_argument("--classification", type=Path, default=EVID / "sensitive-survivor-classification.json")
    parser.add_argument("--verification", type=Path, default=EVID / "phase4-discriminating-test-verification.json")
    parser.add_argument("--baseline", type=Path, default=EVID / "baseline.json")
    parser.add_argument("--out", type=Path, default=EVID / "security-adequacy-gate.json")
    parser.add_argument("--fresh-score", type=float, default=None, help="Phase 8 fresh full-population score")
    args = parser.parse_args()

    pop = json.loads(args.population.read_text())
    cls = json.loads(args.classification.read_text())
    ver = json.loads(args.verification.read_text())
    base = json.loads(args.baseline.read_text())

    score = args.fresh_score if args.fresh_score is not None else pop.get("MUTATION_SCORE_V2")
    score_source = "phase-8-fresh" if args.fresh_score is not None else pop.get("kind")

    targets = [
        m for m in cls["mutants"]
        if m["classification"] == "SURVIVED_KILLABLE" and m["security_class"] in HIGH_CRITICAL
    ]
    high = sum(1 for m in targets if m["security_class"] == "SECURITY_BYPASS")
    critical = sum(
        1 for m in targets if m["security_class"] in ("SECURITY_BYPASS", "PERMISSION_WEAKENING", "INTEGRITY_WEAKENING")
    )
    unresolved = [m for m in targets if m.get("phase4_disposition") not in RESOLVED]
    unresolved_high = [m["id"] for m in unresolved if m["security_class"] == "SECURITY_BYPASS"]
    unresolved_critical = [m["id"] for m in unresolved]
    indeterminate = [m["id"] for m in targets if m.get("phase4_disposition") == "INDETERMINATE"]

    # FINAL_CODE_REPRODUCIBLE_SECURITY_BYPASSES: survivors that stayed
    # classified as a reproducible bypass after remediation (not killed and
    # not proven equivalent on reachable inputs).
    final_bypasses = [
        m["id"]
        for m in targets
        if m["security_class"] == "SECURITY_BYPASS"
        and m.get("phase4_disposition") not in ("KILLED", "EQUIVALENT_PROVEN")
    ]

    global_gate = score is not None and score >= 0.90
    security_adequacy = (
        len(unresolved_high) == 0
        and len(unresolved_critical) == 0
        and len(indeterminate) == 0
        and len(final_bypasses) == 0
    )
    gate_pass = bool(global_gate) and security_adequacy

    result = {
        "schema_version": "mgk.security-mutation-adequacy.v1",
        "kind": "security-mutation-adequacy-gate",
        "recorded_at": "2026-08-17",
        "GLOBAL_MUTATION_SCORE": score,
        "GLOBAL_MUTATION_SCORE_SOURCE": score_source,
        "GLOBAL_MUTATION_THRESHOLD": 0.90,
        "GLOBAL_MUTATION_GATE": "PASS" if global_gate else "FAIL",
        "SECURITY_MUTATION_ADEQUACY": "PASS" if security_adequacy else "FAIL",
        "SECURITY_SENSITIVE_SURVIVORS": len(targets),
        "UNRESOLVED_HIGH": len(unresolved_high),
        "UNRESOLVED_CRITICAL": len(unresolved_critical),
        "SECURITY_SENSITIVE_INDETERMINATE": len(indeterminate),
        "FINAL_CODE_REPRODUCIBLE_SECURITY_BYPASSES": len(final_bypasses),
        "phase4_dispositions": cls.get("phase4_disposition_counts", {}),
        "gate_result": "PASS" if gate_pass else "FAIL",
        "unresolved_high_ids": unresolved_high,
        "unresolved_critical_ids": unresolved_critical,
        "final_bypass_ids": final_bypasses,
        "population": {
            "total": pop.get("population_total"),
            "killed": pop.get("killed"),
            "survived": pop.get("survived"),
            "timeout": pop.get("timeout"),
        },
        "baseline": {
            "test_count": base.get("baseline_results", {}).get("test_count"),
            "official_score": base.get("baseline_results", {}).get("mutation_score"),
        },
    }

    args.out.write_text(json.dumps(result, indent=1) + "\n")
    print(
        f"PHASE_5={'PASS' if gate_pass else 'FAIL'} "
        f"GLOBAL_MUTATION_SCORE={score:.4f} GLOBAL_MUTATION_GATE={'PASS' if global_gate else 'FAIL'} "
        f"SECURITY_MUTATION_ADEQUACY={'PASS' if security_adequacy else 'FAIL'} "
        f"UNRESOLVED_HIGH={len(unresolved_high)} UNRESOLVED_CRITICAL={len(unresolved_critical)} "
        f"INDETERMINATE={len(indeterminate)} FINAL_BYPASSES={len(final_bypasses)}"
    )
    return 0 if gate_pass else 1


if __name__ == "__main__":
    raise SystemExit(main())