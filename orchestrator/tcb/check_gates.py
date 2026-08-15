import json
import sys
from pathlib import Path

from contracts import load_acceptance


def check_gates(results_file):
    document = json.loads(Path(results_file).read_text(encoding="utf-8"))
    if set(document) != {"schema_version", "subject", "results"}:
        raise RuntimeError("Invalid gate-results schema")
    if document["schema_version"] != 1 or not isinstance(document["subject"], str):
        raise RuntimeError("Invalid gate-results metadata")
    if not isinstance(document["results"], list):
        raise RuntimeError("Gate results must be a list")
    statuses = {}
    for item in document["results"]:
        if set(item) != {"gate_id", "status", "evidence"}:
            raise RuntimeError("Invalid gate result item")
        gate_id = item["gate_id"]
        if gate_id in statuses:
            raise RuntimeError(f"Duplicate gate id: {gate_id}")
        if item["status"] not in {"PASS", "FAIL"} or not isinstance(item["evidence"], str):
            raise RuntimeError(f"Invalid gate status: {gate_id}")
        statuses[gate_id] = item["status"]
    acceptance = load_acceptance()
    required = acceptance["required_gates"]
    if set(statuses) != set(required):
        raise RuntimeError("Gate result set does not match functional acceptance")
    failing = [gate_id for gate_id in required if statuses[gate_id] != "PASS"]
    if failing:
        raise RuntimeError(f"Required gates failed: {failing}")
    return True


if __name__ == "__main__":
    try:
        if len(sys.argv) != 2:
            raise RuntimeError("Usage: check_gates.py <gate-results.json>")
        check_gates(sys.argv[1])
        print("All required gates passed.")
    except Exception as exc:
        print(exc)
        raise SystemExit(1)
