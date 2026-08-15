#!/usr/bin/env python3
"""Authorize only deletion of the one-time examiner bootstrap workflow."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess


ONE_TIME_PATH = ".github/workflows/mgk-examiner-bootstrap.yml"


def tracked(root: Path) -> dict[str, tuple[str, str]]:
    completed = subprocess.run(
        ["git", "-C", str(root), "ls-files", "-s", "-z"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    )
    result = {}
    for raw in completed.stdout.split(b"\0"):
        if not raw:
            continue
        metadata, encoded_path = raw.split(b"\t", 1)
        mode, object_id, stage = metadata.decode("ascii").split()
        if stage != "0":
            raise RuntimeError("unmerged index entry")
        path = encoded_path.decode("utf-8", "strict")
        if path in result:
            raise RuntimeError("duplicate tracked path")
        result[path] = (mode, object_id)
    return result


def clean(root: Path) -> bool:
    completed = subprocess.run(
        ["git", "-C", str(root), "status", "--porcelain=v1", "--untracked-files=all"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    )
    return completed.stdout == b""


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--trusted-root", type=Path, required=True)
    parser.add_argument("--candidate-root", type=Path, required=True)
    parser.add_argument("--candidate-sha", required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()

    trusted = args.trusted_root.resolve(strict=True)
    candidate = args.candidate_root.resolve(strict=True)
    trusted_files = tracked(trusted)
    candidate_files = tracked(candidate)
    expected = dict(trusted_files)
    removed = expected.pop(ONE_TIME_PATH, None)
    failures = []
    if removed is None:
        failures.append("trusted bootstrap workflow missing")
    if candidate_files != expected:
        failures.append("candidate differs by more than the authorized one-time deletion")
    if not clean(trusted) or not clean(candidate):
        failures.append("checkout is not clean")

    report = {
        "schema_version": "mgk.bootstrap-cleanup.v1",
        "candidate_sha": args.candidate_sha,
        "authorized_deletion": ONE_TIME_PATH,
        "status": "PASS" if not failures else "FAIL",
        "failures": failures,
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())

