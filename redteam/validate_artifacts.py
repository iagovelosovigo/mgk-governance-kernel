#!/usr/bin/env python3
"""Deterministically validate the independent red-team corpus."""

from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parent
REQUIRED_CATEGORIES = {
    "signature_forgery",
    "payload_mutation",
    "canonicalization_differential",
    "stale_epoch",
    "expiry",
    "nonce_replay",
    "scope_substitution",
    "resource_substitution",
    "path_traversal",
    "symlink",
    "toctou",
    "confused_deputy",
    "audit_tampering",
    "exception_bypass",
    "malformed_parser",
    "race_condition",
    "fail_open",
    "planner_compromise",
}
EXPECTED_KEYS = {
    "decision",
    "reason_code",
    "execution_count",
    "audit_event_present",
    "evidence_preserved",
}
CHECKSUM_FILES = {
    "README.md",
    "adapter-contract.json",
    "attack-matrix.json",
    "findings.json",
    "proof-unbound-gate-subject.json",
    "run_attacks.py",
    "test_redteam_corpus.py",
    "test-vectors.json",
    "threat-model.json",
}
SHA256 = re.compile(r"^[0-9a-f]{64}$")


def load(name: str):
    with (ROOT / name).open("r", encoding="utf-8") as stream:
        return json.load(stream)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def verify_checksums() -> None:
    entries = {}
    previous = None
    for number, raw in enumerate((ROOT / "SHA256SUMS").read_text(encoding="ascii").splitlines(), 1):
        parts = raw.split("  ", 1)
        require(len(parts) == 2 and SHA256.fullmatch(parts[0]) is not None, f"checksum line {number}")
        digest, relative = parts
        path = PurePosixPath(relative)
        require(
            not path.is_absolute() and path.parts and all(part not in {"", ".", ".."} for part in path.parts),
            f"unsafe checksum path: {relative}",
        )
        require(relative not in entries and (previous is None or relative > previous), "checksum paths not sorted")
        entries[relative] = digest
        previous = relative
    require(set(entries) == CHECKSUM_FILES, "checksum coverage mismatch")
    for relative, expected in entries.items():
        target = ROOT / relative
        require(target.is_file() and not target.is_symlink(), f"checksum target invalid: {relative}")
        require(hashlib.sha256(target.read_bytes()).hexdigest() == expected, f"checksum mismatch: {relative}")


def validate() -> dict:
    verify_checksums()
    threat = load("threat-model.json")
    matrix = load("attack-matrix.json")
    vectors = load("test-vectors.json")
    adapter = load("adapter-contract.json")

    for name, document in {
        "threat": threat,
        "matrix": matrix,
        "vectors": vectors,
        "adapter": adapter,
    }.items():
        require(document.get("schema_version") == "1.0", f"{name}: schema_version")

    invariants = {item["id"] for item in threat["required_invariants"]}
    require(len(invariants) == len(threat["required_invariants"]), "duplicate invariant id")
    require("INV-14" in invariants and "INV-15" in invariants, "H14/race invariants absent")

    vector_by_id = {item["id"]: item for item in vectors["vectors"]}
    require(len(vector_by_id) == len(vectors["vectors"]), "duplicate vector id")
    require("RT-000" in vector_by_id, "positive baseline absent")
    operations = set(adapter["supported_step_operations"])
    for vector_id, vector in vector_by_id.items():
        require(vector.get("schema_version") == "1.0", f"{vector_id}: schema")
        require(isinstance(vector.get("steps"), list) and vector["steps"], f"{vector_id}: steps")
        require(EXPECTED_KEYS <= set(vector.get("expected", {})), f"{vector_id}: expected observables")
        require(vector["expected"]["decision"] in {"ALLOW", "DENY"}, f"{vector_id}: decision")
        require(type(vector["expected"]["execution_count"]) is int, f"{vector_id}: execution count")
        for step in vector["steps"]:
            require(step.get("op") in operations, f"{vector_id}: unknown op {step.get('op')}")

    attacks = matrix["attacks"]
    attack_ids = {attack["id"] for attack in attacks}
    require(len(attack_ids) == len(attacks), "duplicate attack id")
    categories = {attack["category"] for attack in attacks}
    require(REQUIRED_CATEGORIES <= categories, f"missing categories: {sorted(REQUIRED_CATEGORIES - categories)}")
    referenced = set()
    for attack in attacks:
        require(attack["severity"] in {"critical", "high", "medium", "low", "informational"}, f"{attack['id']}: severity")
        require(set(attack["target_invariants"]) <= invariants, f"{attack['id']}: unknown invariant")
        require(attack["vector_ids"], f"{attack['id']}: no vectors")
        for vector_id in attack["vector_ids"]:
            require(vector_id in vector_by_id, f"{attack['id']}: missing vector {vector_id}")
            referenced.add(vector_id)
    orphaned = set(vector_by_id) - referenced - {"RT-000"}
    require(not orphaned, f"orphaned attack vectors: {sorted(orphaned)}")

    critical = [attack for attack in attacks if attack["severity"] == "critical"]
    require(len(critical) >= 15, "insufficient critical attack coverage")
    return {
        "schema_version": "1.0",
        "status": "PASS",
        "invariants": len(invariants),
        "attack_categories": len(categories),
        "attacks": len(attacks),
        "vectors": len(vector_by_id),
        "critical_attacks": len(critical),
        "orphaned_vectors": 0,
    }


def main() -> int:
    try:
        result = validate()
    except Exception as exc:
        print(json.dumps({"schema_version": "1.0", "status": "FAIL", "error": str(exc)}, sort_keys=True))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
