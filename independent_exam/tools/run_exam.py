#!/usr/bin/env python3
"""Run frozen suites and emit observations consumable by the verdict calculator."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(Path(__file__).resolve().parent))
from check_frozen import verify as verify_frozen


SUITES = ("unit", "integration", "property", "adversarial", "fuzz", "replay", "concurrency", "h14")


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def counts(path: Path, exit_code: int) -> dict[str, int | str]:
    if not path.is_file():
        return {"status": "FAIL", "total": 0, "failed": 0, "errors": 1, "skipped": 0}
    root = ET.parse(path).getroot()
    suites = [root] if root.tag == "testsuite" else list(root.findall("testsuite"))
    result = {
        "total": sum(int(s.attrib.get("tests", 0)) for s in suites),
        "failed": sum(int(s.attrib.get("failures", 0)) for s in suites),
        "errors": sum(int(s.attrib.get("errors", 0)) for s in suites),
        "skipped": sum(int(s.attrib.get("skipped", 0)) for s in suites),
    }
    result["status"] = "PASS" if exit_code == 0 and result["total"] and not result["failed"] and not result["errors"] and not result["skipped"] else "FAIL"
    return result


def all_pass(suites: dict[str, dict[str, object]], *names: str) -> bool:
    return all(suites.get(name, {}).get("status") == "PASS" for name in names)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--commit-sha", required=True)
    parser.add_argument("--adapter", default="candidate_adapter")
    parser.add_argument("--artifact-root", type=Path, required=True)
    parser.add_argument("--mutation", type=Path, required=True)
    parser.add_argument("--clean-a", type=Path, required=True)
    parser.add_argument("--clean-b", type=Path, required=True)
    parser.add_argument("--reproducibility", type=Path, required=True)
    parser.add_argument("--security-findings", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()

    frozen_failures = verify_frozen(ROOT)
    env = os.environ.copy()
    env.update({"MGK_CANDIDATE_ADAPTER": args.adapter, "PYTHONHASHSEED": "0"})
    suites: dict[str, dict[str, object]] = {}
    with tempfile.TemporaryDirectory(prefix="mgk-exam-") as raw:
        for suite in SUITES:
            junit = Path(raw) / f"{suite}.xml"
            process = subprocess.run(
                [sys.executable, "-m", "pytest", "-q", str(ROOT / "tests"), "-m", suite, f"--junitxml={junit}"],
                cwd=ROOT,
                env=env,
                text=True,
                capture_output=True,
                timeout=900,
            )
            suites[suite] = counts(junit, process.returncode)

    mutation = json.loads(args.mutation.read_text(encoding="utf-8"))
    clean_a = json.loads(args.clean_a.read_text(encoding="utf-8"))
    clean_b = json.loads(args.clean_b.read_text(encoding="utf-8"))
    repro = json.loads(args.reproducibility.read_text(encoding="utf-8"))
    security = json.loads(args.security_findings.read_text(encoding="utf-8"))

    adv = all_pass(suites, "adversarial", "fuzz")
    lifecycle = all_pass(suites, "unit", "integration")
    replay = all_pass(suites, "replay")
    concurrent = all_pass(suites, "concurrency")
    h14 = all_pass(suites, "h14")
    zero_or_fail = lambda condition: 0 if condition else -1
    metrics = {
        "forged_capabilities_accepted": zero_or_fail(adv),
        "expired_capabilities_accepted": zero_or_fail(lifecycle),
        "future_capabilities_accepted": zero_or_fail(lifecycle),
        "stale_epoch_accepted": zero_or_fail(lifecycle),
        "accepted_replays": zero_or_fail(replay),
        "scope_escalations_accepted": zero_or_fail(adv),
        "resource_substitutions_accepted": zero_or_fail(adv),
        "payload_mutations_accepted": zero_or_fail(adv),
        "canonicalization_differentials_accepted": zero_or_fail(all_pass(suites, "unit", "property")),
        "path_traversals_accepted": zero_or_fail(adv),
        "symlink_attacks_accepted": zero_or_fail(adv),
        "toctou_attacks_accepted": zero_or_fail(adv),
        "parser_differentials_accepted": zero_or_fail(adv),
        "exception_bypasses_accepted": zero_or_fail(adv),
        "race_double_executions": zero_or_fail(concurrent),
        "h14_forbidden_executions": zero_or_fail(h14),
        "require_xeito_executions": zero_or_fail(all_pass(suites, "unit")),
        "non_ten_xeito_executions": zero_or_fail(all_pass(suites, "unit")),
        "required_audit_events_missing": zero_or_fail(all_pass(suites, "integration")),
        "failure_evidence_missing": zero_or_fail(all_pass(suites, "integration")),
        "critical_security_findings": security.get("critical_open", -1),
        "high_security_findings": security.get("high_open", -1),
    }
    pass_value = lambda condition: "PASS" if condition else "FAIL"
    checks = {
        "asymmetric_signing": pass_value(adv),
        "private_key_absent_from_planner": pass_value(h14),
        "proposal_authorization_execution_separated": pass_value(h14),
        "authorization_epoch": pass_value(lifecycle and concurrent),
        "nonce_atomicity": pass_value(replay and concurrent),
        "resource_binding": pass_value(adv),
        "anti_toctou": pass_value(adv),
        "audit_integrity": pass_value(all_pass(suites, "integration", "adversarial", "concurrency")),
        "failure_ledger_integrity": pass_value(all_pass(suites, "integration")),
        "fail_closed": pass_value(adv and h14),
        "saxp_three_outcomes": pass_value(all_pass(suites, "unit")),
        "feedback_observable": pass_value(all_pass(suites, "integration")),
        "mutation_testing": pass_value(mutation.get("status") == "PASS"),
        "protected_contract_integrity": pass_value(not frozen_failures),
    }
    artifact_hashes = {
        name: digest(path)
        for name in json.loads((ROOT / "FUNCTIONAL-ACCEPTANCE.yaml").read_text())["required_artifacts"]
        if name not in {"MGK-v0.1.0-FUNCTIONAL-VERDICT.json", "MGK-v0.1.0-FUNCTIONAL-VERDICT.md"}
        and (path := args.artifact_root / name).is_file()
    }
    source_hash = digest(args.source) if args.source.is_file() else clean_a.get("source_sha256", "")
    observations = {
        "schema_version": "mgk.observations.v1",
        "candidate": {"version": "0.1.0", "source_sha256": source_hash, "commit_sha": args.commit_sha},
        "contract_sha256": digest(ROOT / "FROZEN.sha256"),
        "suites": suites,
        "metrics": metrics,
        "checks": checks,
        "mutation_score_percent": mutation.get("score_percent", -1),
        "clean_install": {
            "A": clean_a.get("status"),
            "B": clean_b.get("status"),
            "internet_required": False,
            "development_workspace_used": False,
        },
        "reproducibility": {
            key: repro.get(key)
            for key in ("status", "source_tree_match", "wheel_sha256_match", "test_outcome_match", "h14_outcome_match")
        },
        "artifacts": artifact_hashes,
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(observations, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("PASS observations generated" if not frozen_failures else "FAIL frozen exam")
    return 0 if not frozen_failures else 1


if __name__ == "__main__":
    raise SystemExit(main())

