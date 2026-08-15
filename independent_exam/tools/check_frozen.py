#!/usr/bin/env python3
"""Verify every protected examination file against FROZEN.sha256."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def verify(root: Path = ROOT) -> list[str]:
    manifest = root / "FROZEN.sha256"
    failures: list[str] = []
    if not manifest.is_file():
        return ["FROZEN.sha256 missing"]
    listed: set[str] = set()
    for number, raw in enumerate(manifest.read_text(encoding="utf-8").splitlines(), 1):
        if not raw.strip():
            continue
        try:
            expected, relative = raw.split("  ", 1)
        except ValueError:
            failures.append(f"line {number}: malformed")
            continue
        if relative.startswith("/") or ".." in Path(relative).parts:
            failures.append(f"line {number}: unsafe path {relative!r}")
            continue
        target = root / relative
        listed.add(relative)
        if not target.is_file():
            failures.append(f"missing: {relative}")
            continue
        actual = hashlib.sha256(target.read_bytes()).hexdigest()
        if actual != expected:
            failures.append(f"hash mismatch: {relative}")
    protected = {
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file()
        and path.name != "FROZEN.sha256"
        and "__pycache__" not in path.parts
        and not path.name.endswith(".pyc")
    }
    for missing in sorted(protected - listed):
        failures.append(f"unfrozen protected file: {missing}")
    return failures


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=ROOT)
    args = parser.parse_args()
    failures = verify(args.root.resolve())
    if failures:
        for failure in failures:
            print(f"FAIL {failure}")
        return 1
    print("PASS frozen examination integrity")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

