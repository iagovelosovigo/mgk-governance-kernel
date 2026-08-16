#!/usr/bin/env python3
"""Build mutation-v2-classification.json from a mutmut results dump + mutants src.

Per-mutant evidence: the mutation diff (orig vs variant) is extracted from the
trampolined mutant source and attached to every record.
"""

from __future__ import annotations

import argparse
import ast
import json
from pathlib import Path

from mutation_classifier_v2 import classify_mutant


def load_functions(path: Path) -> dict[str, str]:
    text = path.read_text()
    tree = ast.parse(text)
    funcs = {}
    lines = text.splitlines(True)
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            funcs[node.name] = "".join(lines[node.lineno - 1 : node.end_lineno])
    return funcs


def diff_compact(orig: str, variant: str) -> str:
    import difflib

    a, b = orig.splitlines(), variant.splitlines()
    out = []
    for tag, i1, i2, j1, j2 in difflib.SequenceMatcher(None, a, b).get_opcodes():
        if tag == "equal":
            continue
        for line in a[i1:i2]:
            out.append("- " + line)
        for line in b[j1:j2]:
            out.append("+ " + line)
    return "\n".join(out)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mutants-root", type=Path, required=True, help="mutants/ directory from the mutmut run")
    parser.add_argument("--results", type=Path, required=True, help="mutmut per-mutant results dump")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--reclassified-killed", action="append", default=[], help="mutant id reclassified KILLED by spot-check")
    parser.add_argument("--reclassified-evidence", action="append", default=[], help="evidence string for reclassified mutants")
    args = parser.parse_args()

    import re as _re

    status = {}
    for line in args.results.read_text().splitlines():
        m = _re.match(r"\s+(\S+): (killed|survived|timeout|no tests|suspicious)", line)
        if m:
            status[m.group(1)] = m.group(2)

    mgk = args.mutants_root / "src" / "mgk"
    cache: dict[str, dict[str, str]] = {}
    rows = []
    for mid, st in sorted(status.items()):
        parts = mid.split(".")
        mod = parts[1]
        funcid = ".".join(parts[2:])
        base = funcid.split("__mutmut_")[0]
        idx = funcid.split("__mutmut_")[1]
        rec = {
            "id": mid,
            "module": mod,
            "function": base,
            "mutant_index": idx,
            "run_status": st,
        }
        if st in ("survived", "timeout"):
            f = mgk / f"{mod}.py"
            if mod not in cache:
                cache[mod] = load_functions(f)
            funcs = cache[mod]
            orig = funcs.get(base + "__mutmut_orig")
            variant = funcs.get(funcid)
            if orig is None or variant is None:
                rec["classification"] = "INDETERMINATE"
                rec["justification"] = "mutation diff could not be extracted"
                rec["evidence"] = f"orig={orig is not None} variant={variant is not None}"
            else:
                diff = diff_compact(orig, variant)
                rec["evidence"] = diff[:1200]
                if mid in args.reclassified_killed:
                    rec["classification"] = "KILLED"
                    rec["justification"] = args.reclassified_evidence[0] if args.reclassified_evidence else "reclassified by spot-check"
                else:
                    cat, just, labels = classify_mutant(mid, st, diff)
                    rec["classification"] = cat
                    rec["justification"] = just
                    rec["family"] = labels
        else:
            rec["classification"] = "KILLED" if st == "killed" else "INDETERMINATE"
            rec["justification"] = "mutmut reported killed" if st == "killed" else "un-evaluated (no covering test); requires coverage"
        rows.append(rec)

    from collections import Counter

    counts = Counter(r["classification"] for r in rows)
    doc = {
        "schema_version": "mgk.mutation.classification.v2",
        "contract_id": "MGK-v0.1.0-mutation-gate-2",
        "source_results": str(args.results),
        "counts": dict(counts),
        "mutants": rows,
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(doc, indent=1, ensure_ascii=False) + "\n")
    print(json.dumps(dict(counts)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())