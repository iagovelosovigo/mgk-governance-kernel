#!/usr/bin/env python3
"""Phase 4: prove the new discriminating tests kill the HIGH/CRITICAL survivors.

For each security-sensitive survivor classified SECURITY_BYPASS,
PERMISSION_WEAKENING or INTEGRITY_WEAKENING, this tool:
  1. parses the exact old_fragment -> new_fragment from the recorded diff,
  2. copies the pristine v0.2.0 src into a disposable directory,
  3. applies the mutant transformation,
  4. runs `pytest tests/test_mutation_v3_security.py` against the pristine and
     the mutated copy (PYTHONPATH resolving mgk to the copy),
  5. records KILLED if the mutant copy fails at least one test while the
     pristine copy passes all.

A mutant that still passes all new tests is recorded as TEST_GAP_ONLY (needs a
discriminating test) and the run FAILS, because Phase 5 forbids unresolved
HIGH/CRITICAL survivors.
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
TEST_FILE = "tests/test_mutation_v3_security.py"
HIGH_CRITICAL = ("SECURITY_BYPASS", "PERMISSION_WEAKENING", "INTEGRITY_WEAKENING")


def unmangle_name(mangled: str) -> str:
    """Map a mutmut-mangled name back to the real source identifier.

    Handles both `xǁClassǁmethod__mutmut_N` and `x_name__mutmut_orig` forms.
    """
    name = mangled
    if "ǁ" in name:
        name = name.rsplit("ǁ", 1)[1]
    elif name.startswith("x_"):
        name = name[2:]
    marker = name.find("__mutmut_")
    if marker != -1:
        name = name[:marker]
    return name


def _diff_content(content: str) -> str:
    if content.startswith(" "):
        content = content[1:]
    return content


def _unmangle_def(line: str) -> str:
    """Rewrite a mangled `def` line to use the real function name so a
    signature-only mutation (e.g. a changed default argument) survives the
    name-rename noise and is applied to the source."""
    stripped = line.lstrip()
    if not stripped.startswith("def "):
        return line
    name = stripped.split("(", 1)[0].split(" ", 1)[1].strip()
    real = unmangle_name(name)
    indent = line[: len(line) - len(stripped)]
    return f"{indent}def {real}({stripped.split('(', 1)[1]}"


def parse_diff(diff: str) -> list[tuple[str, str]]:
    old_lines: list[str] = []
    new_lines: list[str] = []
    for raw in diff.splitlines():
        if raw.startswith("---") or raw.startswith("+++"):
            continue
        if raw.startswith("-"):
            old_lines.append(_unmangle_def(_diff_content(raw[1:])))
        elif raw.startswith("+"):
            new_lines.append(_unmangle_def(_diff_content(raw[1:])))
    while old_lines and new_lines:
        if old_lines[0] == new_lines[0] and old_lines[0].lstrip().startswith("def "):
            old_lines.pop(0)
            new_lines.pop(0)
        else:
            break
    if len(old_lines) != len(new_lines):
        return [("\n".join(old_lines), "\n".join(new_lines))]
    pairs = []
    for old, new in zip(old_lines, new_lines):
        if old != new:
            pairs.append((old, new))
    return pairs


def unmangle(mangled: str) -> str:
    if "ǁ" in mangled:
        return mangled.rsplit("ǁ", 1)[1]
    if mangled.startswith("x_"):
        return mangled[2:]
    return mangled


def function_body(lines: list[str], fn: str) -> tuple[int, int]:
    start = None
    for i, line in enumerate(lines):
        stripped = line.lstrip()
        if stripped.startswith("def ") or stripped.startswith("async def "):
            name = stripped.split("(", 1)[0].split(" ", 1)[1].strip()
            if name == fn:
                start = i
                break
    if start is None:
        raise SystemExit(f"FAIL_CLOSED: def {fn} not found in module")
    indent = len(lines[start]) - len(lines[start].lstrip())
    end = len(lines)
    for j in range(start + 1, len(lines)):
        line = lines[j]
        stripped = line.lstrip()
        if (stripped.startswith("def ") or stripped.startswith("async def ") or stripped.startswith("class ")) and (
            len(line) - len(line.lstrip())
        ) <= indent:
            end = j
            break
    return start, end


def apply_mutation(src_file: Path, fn: str, old_fragment: str, new_fragment: str) -> None:
    lines = src_file.read_text().splitlines()
    start, end = function_body(lines, fn)
    body = "\n".join(lines[start:end])
    if old_fragment not in body:
        raise SystemExit(
            f"FAIL_CLOSED: block not found in {src_file} {fn}:\n{old_fragment!r}\n--- in source ---\n{body[-1500:]}"
        )
    body = body.replace(old_fragment, new_fragment, 1)
    src_file.write_text("\n".join(lines[:start]) + "\n" + body + "\n" + "\n".join(lines[end:]) + "\n")


def run_tests(copy_root: Path | None, tmp_dir: Path, test_file: str = TEST_FILE) -> dict:
    env = dict(__import__("os").environ)
    if copy_root is not None:
        env["PYTHONPATH"] = str(copy_root / "src")
    proc = subprocess.run(
        [str(VENV_PY), "-m", "pytest", test_file, "-q"],
        capture_output=True,
        text=True,
        timeout=600,
        env=env,
        cwd=str(tmp_dir),
    )
    return {"exit_code": proc.returncode, "stdout": proc.stdout, "stderr": proc.stderr}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--classification", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--test-file", default=TEST_FILE, help="test file that must kill the targets")
    parser.add_argument("--ids", default=None, help="comma-separated subset of mutant ids to verify")
    args = parser.parse_args()

    data = json.loads(args.classification.read_text())
    ids_subset = set(args.ids.split(",")) if args.ids else None
    targets = [
        m
        for m in data["mutants"]
        if m["classification"] == "SURVIVED_KILLABLE"
        and m["security_class"] in HIGH_CRITICAL
        and m.get("diff")
        and (ids_subset is None or m["id"] in ids_subset)
    ]
    if not targets:
        print("PHASE_4=NO_TARGETS")
        return 0

    tmp = Path(tempfile.mkdtemp(prefix="mgk-v4-"))
    pristine = tmp / "pristine"
    shutil.copytree(SRC, pristine / "src")
    baseline = run_tests(pristine, REPO_ROOT, args.test_file)
    if baseline["exit_code"] != 0:
        print("FAIL_CLOSED: pristine copy fails the new tests")
        print(baseline["stdout"][-2000:])
        print(baseline["stderr"][-2000:])
        return 2

    records = []
    unresolved = []
    for mutant in targets:
        mid = mutant["id"]
        module_file = f"{mutant['module']}.py"
        copy = tmp / mid.replace(":", "_").replace("ǁ", "_")
        shutil.copytree(SRC, copy / "src")
        src_file = copy / "src" / "mgk" / module_file
        if not src_file.exists():
            records.append(
                {
                    "id": mid,
                    "result": "MISSING_MODULE",
                    "reason": f"no src/mgk/{module_file}",
                }
            )
            unresolved.append(mid)
            continue
        for old_fragment, new_fragment in parse_diff(mutant["diff"]):
            apply_mutation(src_file, unmangle(mutant["function"]), old_fragment, new_fragment)
        result = run_tests(copy, REPO_ROOT, args.test_file)
        killed = result["exit_code"] != 0
        records.append(
            {
                "id": mid,
                "module": mutant["module"],
                "function": mutant["function"],
                "security_class": mutant["security_class"],
                "killed_by_new_tests": killed,
                "test_exit_code": result["exit_code"],
            }
        )
        if killed:
            print(f"KILLED    {mid}")
        else:
            print(f"TEST_GAP  {mid}")
            unresolved.append(mid)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(
        json.dumps(
            {
                "schema_version": "mgk.security-mutation-adequacy.v1",
                "kind": "phase-4-discriminating-test-verification",
                "baseline_pass": baseline["exit_code"] == 0,
                "targets": len(targets),
                "killed": sum(1 for r in records if r.get("killed_by_new_tests")),
                "test_gap": len(unresolved),
                "unresolved_ids": unresolved,
                "records": records,
            },
            indent=1,
        )
        + "\n"
    )
    verdict = "FAIL" if unresolved else "PASS"
    print(f"PHASE_4={verdict} KILLED={sum(1 for r in records if r.get('killed_by_new_tests'))} TEST_GAP={len(unresolved)}")
    return 1 if unresolved else 0


if __name__ == "__main__":
    raise SystemExit(main())
