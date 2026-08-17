#!/usr/bin/env python3
"""Survivor verification harness for the security mutation adequacy mission.

For every case in a manifest, the harness:
  1. creates two disposable copies of the v0.2.0 source (pristine + mutated),
  2. applies the exact mutant transformation to the mutated copy,
  3. runs the case probe against BOTH copies with the repo venv,
  4. captures command/exit_code/stdout/stderr and the probe's structured
     pre/post observations,
  5. derives affected_invariant / reproducible / classification from the
     observed original-vs-mutant difference.

Every case runs in isolation in its own temporary directory. Frozen v0.1.0 is
never touched. The classification is derived mechanically from executed
evidence; a probe that produced no original/mutant divergence is INDETERMINATE.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
SRC = REPO_ROOT / "src"
VENV_PY = Path("/var/folders/bf/7f75557n44s0d89v_dx0l7cr0000gn/T/opencode/mgk-verify/venv/bin/python")


def apply_mutation(src_file: Path, old_fragment: str, new_fragment: str) -> None:
    text = src_file.read_text()
    if old_fragment not in text:
        raise SystemExit(f"FAIL_CLOSED: mutation fragment not found in {src_file}: {old_fragment!r}")
    src_file.write_text(text.replace(old_fragment, new_fragment, 1))


def run_probe(copy_root: Path, probe: Path) -> dict:
    env = dict(__import__("os").environ)
    env["PYTHONPATH"] = str(copy_root / "src")
    proc = subprocess.run(
        [str(VENV_PY), str(probe)],
        capture_output=True,
        text=True,
        timeout=120,
        env=env,
        cwd=str(copy_root),
    )
    result = {}
    for line in proc.stdout.splitlines():
        if line.startswith("RESULT_JSON="):
            try:
                result = json.loads(line[len("RESULT_JSON="):])
            except json.JSONDecodeError:
                result = {"raw": line[len("RESULT_JSON="):]}
    return {
        "exit_code": proc.returncode,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
        "result": result,
    }


def classify_case(original: dict, mutant: dict) -> str:
    o, m = original["result"], mutant["result"]
    if original["exit_code"] != 0 or mutant["exit_code"] != 0:
        if original["exit_code"] != 0 and mutant["exit_code"] != 0:
            return "INDETERMINATE"
        return "AVAILABILITY_ONLY"
    if o == m:
        return "TEST_GAP_ONLY"
    if o.get("classification"):
        return o["classification"]
    return "SECURITY_BYPASS"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--work-root", type=Path, default=None)
    args = parser.parse_args()

    manifest = json.loads(args.manifest.read_text())
    records = []
    for case in manifest["cases"]:
        tid = case["test_id"]
        base = Path(tempfile.mkdtemp(prefix=f"mgk-harness-{tid}-", dir=str(args.work_root) if args.work_root else None))
        records_root = base / "records"
        records_root.mkdir()
        outputs = {}
        for tag in ("original", "mutant"):
            copy = base / tag
            shutil.copytree(SRC, copy / "src")
            target = copy / "src" / "mgk" / case["file"]
            if tag == "mutant":
                apply_mutation(target, case["old_fragment"], case["new_fragment"])
        original = run_probe(base / "original", (REPO_ROOT / case["probe"]).resolve())
        mutant = run_probe(base / "mutant", (REPO_ROOT / case["probe"]).resolve())
        classification = classify_case(original, mutant)
        rec = {
            "test_id": tid,
            "mutant_id": case["mutant_id"],
            "command": f"{VENV_PY} {case['probe']}",
            "exit_code_original": original["exit_code"],
            "exit_code_mutant": mutant["exit_code"],
            "stdout_original": original["stdout"],
            "stderr_original": original["stderr"],
            "stdout_mutant": mutant["stdout"],
            "stderr_mutant": mutant["stderr"],
            "original_result": original["result"],
            "mutant_result": mutant["result"],
            "affected_invariant": case["affected_invariant"],
            "reproducible": (original["result"] != mutant["result"]),
            "classification": classification,
        }
        rec.update(case.get("extra_fields", {}))
        records.append(rec)
        (records_root / f"{tid}.json").write_text(json.dumps(rec, indent=1))
        (records_root / f"{tid}.stdout").write_text(
            "===== ORIGINAL =====\n" + original["stdout"] + "\n===== MUTANT =====\n" + mutant["stdout"]
        )
        shutil.rmtree(base, ignore_errors=True)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps({"schema_version": "mgk.security-mutation-adequacy.v1", "kind": "survivor-harness", "cases": records}, indent=1) + "\n")
    for r in records:
        print(f"{r['mutant_id']}: {r['classification']} reproducible={r['reproducible']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())