#!/usr/bin/env python3
"""Run the immutable MGK examination against one exact candidate checkout."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time


COMMIT_SHA = re.compile(r"^[0-9a-f]{40,64}$")


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _run(name: str, command: list[str], *, cwd: Path, env: dict[str, str], timeout: int) -> dict:
    started = time.monotonic()
    try:
        completed = subprocess.run(
            command,
            cwd=cwd,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )
        stdout = completed.stdout
        stderr = completed.stderr
        return_code = completed.returncode
        timed_out = False
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout or b""
        stderr = exc.stderr or b""
        return_code = 124
        timed_out = True
    return {
        "name": name,
        "status": "PASS" if return_code == 0 and not timed_out else "FAIL",
        "exit_code": return_code,
        "timed_out": timed_out,
        "duration_ms": round((time.monotonic() - started) * 1000),
        "stdout_sha256": _digest(stdout),
        "stderr_sha256": _digest(stderr),
        "stdout_tail": stdout.decode("utf-8", "replace")[-4000:],
        "stderr_tail": stderr.decode("utf-8", "replace")[-4000:],
    }


def _require_directory(path: Path, label: str) -> Path:
    resolved = path.resolve(strict=True)
    if not resolved.is_dir():
        raise ValueError(f"{label} is not a directory")
    return resolved


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--trusted-root", type=Path, required=True)
    parser.add_argument("--candidate-root", type=Path, required=True)
    parser.add_argument("--candidate-sha", required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()

    trusted = _require_directory(args.trusted_root, "trusted root")
    candidate = _require_directory(args.candidate_root, "candidate root")
    if trusted == candidate or trusted in candidate.parents or candidate in trusted.parents:
        raise ValueError("trusted and candidate roots must be disjoint")
    if not COMMIT_SHA.fullmatch(args.candidate_sha):
        raise ValueError("candidate SHA is invalid")

    # Keep the venv launcher path. Resolving its symlink would discard the
    # environment and invoke the base interpreter without gate dependencies.
    python = Path(sys.executable).absolute()
    base_env = os.environ.copy()
    base_env.update(
        {
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONHASHSEED": "0",
            "PYTEST_ADDOPTS": "",
        }
    )
    candidate_env = dict(base_env)
    candidate_env["PYTHONPATH"] = str(candidate / "src")
    independent_env = dict(base_env)
    independent_env.update(
        {
            "MGK_CANDIDATE_ADAPTER": "candidate_adapter",
            "PYTHONPATH": os.pathsep.join((str(trusted), str(candidate / "src"))),
        }
    )

    with tempfile.TemporaryDirectory(prefix="mgk-protected-") as temporary:
        temporary_path = Path(temporary)
        redteam_out = temporary_path / "redteam-results.json"
        h14_workdir = temporary_path / "h14"
        checks = [
            _run(
                "candidate_tests",
                [str(python), "-m", "pytest", "-q", "tests"],
                cwd=candidate,
                env=candidate_env,
                timeout=600,
            ),
            _run(
                "independent_frozen_exam",
                [
                    str(python),
                    "-m",
                    "pytest",
                    "-q",
                    "-p",
                    "exam_hypothesis_profile",
                    "tests",
                ],
                cwd=trusted / "independent_exam",
                env=independent_env,
                timeout=1200,
            ),
            _run(
                "independent_red_team",
                [
                    str(python),
                    str(trusted / "redteam" / "run_attacks.py"),
                    "--out",
                    str(redteam_out),
                    "--adapter-command",
                    str(python),
                    str(trusted / "redteam" / "candidate_attack_adapter.py"),
                ],
                cwd=trusted,
                env=candidate_env,
                timeout=900,
            ),
            _run(
                "h14_smoke",
                [
                    str(python),
                    "-m",
                    "mgk.cli",
                    "h14-smoke",
                    "--workdir",
                    str(h14_workdir),
                ],
                cwd=candidate,
                env=candidate_env,
                timeout=120,
            ),
        ]

        redteam = None
        if redteam_out.is_file():
            try:
                redteam = json.loads(redteam_out.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                redteam = None
        if not isinstance(redteam, dict) or redteam.get("status") != "PASS":
            for check in checks:
                if check["name"] == "independent_red_team":
                    check["status"] = "FAIL"

    passed = all(check["status"] == "PASS" for check in checks)
    report = {
        "schema_version": "mgk.protected-gates.v1",
        "candidate_sha": args.candidate_sha,
        "trusted_root_sha256": hashlib.sha256(
            (trusted / "contracts" / "ROOT_MANIFEST.sha256").read_bytes()
        ).hexdigest(),
        "status": "PASS" if passed else "FAIL",
        "checks": checks,
        "redteam": {
            key: redteam.get(key)
            for key in ("status", "total", "passed", "failed")
        }
        if isinstance(redteam, dict)
        else None,
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
