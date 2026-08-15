#!/usr/bin/env python3
"""Run declarative attack vectors against an isolated JSON adapter command."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def subset_matches(expected, observed, path="observed"):
    failures = []
    if isinstance(expected, dict):
        if not isinstance(observed, dict):
            return [f"{path}: expected object"]
        for key, value in expected.items():
            if key not in observed:
                failures.append(f"{path}.{key}: missing")
            else:
                failures.extend(subset_matches(value, observed[key], f"{path}.{key}"))
    elif expected != observed:
        failures.append(f"{path}: expected {expected!r}, got {observed!r}")
    return failures


def run_vector(command, vector, timeout):
    started = time.monotonic()
    try:
        completed = subprocess.run(
            command,
            input=json.dumps(vector, sort_keys=True).encode("utf-8"),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return {"id": vector["id"], "status": "FAIL", "failure": "ADAPTER_TIMEOUT"}
    duration_ms = round((time.monotonic() - started) * 1000)
    if completed.returncode != 0:
        return {
            "id": vector["id"],
            "status": "FAIL",
            "failure": "ADAPTER_NONZERO",
            "exit_code": completed.returncode,
            "stderr": completed.stderr.decode("utf-8", "replace")[-2000:],
            "duration_ms": duration_ms,
        }
    try:
        result = json.loads(completed.stdout.decode("utf-8", "strict"))
    except Exception as exc:
        return {
            "id": vector["id"],
            "status": "FAIL",
            "failure": "ADAPTER_INVALID_JSON",
            "detail": str(exc),
            "duration_ms": duration_ms,
        }
    if result.get("schema_version") != "1.0" or result.get("test_id") != vector["id"]:
        return {"id": vector["id"], "status": "FAIL", "failure": "ADAPTER_SCHEMA", "duration_ms": duration_ms}
    failures = subset_matches(vector["expected"], result.get("observed"))
    return {
        "id": vector["id"],
        "category": vector["category"],
        "status": "PASS" if not failures else "FAIL",
        "failures": failures,
        "duration_ms": duration_ms,
    }


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--vectors", default=str(ROOT / "test-vectors.json"))
    parser.add_argument("--select", action="append", default=[])
    parser.add_argument("--timeout", type=int, default=15)
    parser.add_argument("--out")
    parser.add_argument("--adapter-command", nargs=argparse.REMAINDER, required=True)
    args = parser.parse_args(argv)
    command = list(args.adapter_command)
    if command and command[0] == "--":
        command.pop(0)
    if not command:
        parser.error("adapter command is empty")
    corpus = json.loads(Path(args.vectors).read_text(encoding="utf-8"))
    selected = set(args.select)
    tests = [item for item in corpus["vectors"] if not selected or item["id"] in selected]
    results = [run_vector(command, item, args.timeout) for item in tests]
    report = {
        "schema_version": "1.0",
        "status": "PASS" if all(item["status"] == "PASS" for item in results) else "FAIL",
        "total": len(results),
        "passed": sum(item["status"] == "PASS" for item in results),
        "failed": sum(item["status"] == "FAIL" for item in results),
        "results": results,
    }
    encoded = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.out:
        Path(args.out).write_text(encoded, encoding="utf-8")
    sys.stdout.write(encoded)
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
