#!/usr/bin/env python3
"""Deterministic security classification of sensitive survivors.

Reads sensitive-survivors.json (produced by extract_sensitive_survivors.py) and
applies the MGK-MUTATION-GATE-V2 classifier to each survivor, then maps the
transformation family onto the security adequacy vocabulary:

  SECURITY_BYPASS          security check disabled/weakened (grant without valid authority)
  PERMISSION_WEAKENING     capability/scope boundary weakened
  INTEGRITY_WEAKENING      integrity/authenticity/audit guarantee weakened
  AVAILABILITY_ONLY        only availability/robustness affected, no security invariant
  TEST_GAP_ONLY            behavior change but no security invariant implicated
  EQUIVALENT_PROVEN        classifier-proven no behavioral difference
  INDETERMINATE            classifier cannot determine

No LLM judgement: family -> security-class mapping is rule-based and applied
identically for every survivor, so re-running reproduces the exact output.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from mutation_classifier_v2 import classify_mutant  # noqa: E402

SECURITY_MODULES = {
    "authority", "crypto", "executor", "resource", "saxp", "state", "verifier",
    "canonical", "ledger", "models",
}

# family -> adequacy class for security-sensitive modules
FAMILY_CLASS = {
    "DEFAULT_ARG": "PERMISSION_WEAKENING",
    "CONDITION_CHANGE": "SECURITY_BYPASS",
    "BOOLEAN_SWAP": "SECURITY_BYPASS",
    "OPERATOR_CHANGE": "SECURITY_BYPASS",
    "REMOVED_STMT": "SECURITY_BYPASS",
    "RETURN_CHANGE": "INTEGRITY_WEAKENING",
    "ASSIGN_RHS": "INTEGRITY_WEAKENING",
    "CALL_ARG": "PERMISSION_WEAKENING",
    "NUMBER_CONST": "PERMISSION_WEAKENING",
    "STRING_CONST": "INTEGRITY_WEAKENING",
    "STRING_CASE_ONLY": "TEST_GAP_ONLY",
    "MULTI_BODY": "SECURITY_BYPASS",
    "ADDED_STMT": "TEST_GAP_ONLY",
    "OTHER_TOKEN": "TEST_GAP_ONLY",
    "RAISE_ARGS": "AVAILABILITY_ONLY",
    "NOOP": "EQUIVALENT_PROVEN",
    "SQL_CASE_ONLY": "EQUIVALENT_PROVEN",
    "JSON_FLAG_FALSY": "EQUIVALENT_PROVEN",
    "GETATTR_DEFAULT_ONLY": "EQUIVALENT_PROVEN",
    "RESOLVE_STRICT_ONLY": "EQUIVALENT_PROVEN",
    "FS_PATH_CASE_ONLY": "EQUIVALENT_PROVEN",
    "ENCODE_HANDLER": "EQUIVALENT_PROVEN",
    "CODEC_CASE_ONLY": "EQUIVALENT_PROVEN",
    "UNKNOWN": "INDETERMINATE",
}

# overrides for proven-equivalence labels that denote security-neutral behavior
EQUIV_CLASS = "EQUIVALENT_PROVEN"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--survivors", type=Path, required=True, help="sensitive-survivors.json")
    parser.add_argument("--out-json", type=Path, required=True)
    parser.add_argument("--out-md", type=Path, required=True)
    args = parser.parse_args()

    data = json.loads(args.survivors.read_text())
    rows = []
    for m in data["mutants"]:
        cat, just, labels = classify_mutant(m["id"], "survived", m["diff"])
        fam = labels[0] if labels else "UNKNOWN"
        if cat == "EQUIVALENT_PROVEN":
            sec = EQUIV_CLASS
        else:
            sec = FAMILY_CLASS.get(fam, "TEST_GAP_ONLY")
            if sec == "SECURITY_BYPASS" and m["module"] in ("cli", "cha"):
                sec = "TEST_GAP_ONLY"
        rows.append(
            {
                "id": m["id"],
                "module": m["module"],
                "function": m["function"],
                "mutant_index": m["mutant_index"],
                "family": fam,
                "classification": cat,
                "security_class": sec,
                "justification": just,
                "diff": m["diff"],
            }
        )

    from collections import Counter

    by_class = Counter(r["security_class"] for r in rows)
    by_module_class = {}
    for r in rows:
        by_module_class.setdefault(r["module"], Counter())[r["security_class"]] += 1

    doc = {
        "schema_version": "mgk.security-mutation-adequacy.v1",
        "kind": "sensitive-survivor-classification",
        "source": str(args.survivors),
        "counts_by_class": dict(by_class),
        "counts_by_module_and_class": {m: dict(c) for m, c in by_module_class.items()},
        "mutants": rows,
    }
    payload = json.dumps(doc, indent=1)
    args.out_json.parent.mkdir(parents=True, exist_ok=True)
    args.out_json.write_text(payload + "\n")
    sha = hashlib.sha256(args.out_json.read_bytes()).hexdigest()
    args.out_json.with_name(args.out_json.name + ".sha256").write_text(sha + "\n")

    md = [
        "# Sensitive Survivor Security Classification",
        "",
        f"- source: `{args.survivors}`",
        f"- total: **{len(rows)}**",
        "- SHA-256: `%s`" % sha,
        "",
        "## Counts by security class",
        "",
        "| class | count |",
        "|---|---|",
    ]
    for c, n in sorted(by_class.items()):
        md.append(f"| {c} | {n} |")
    md.append("")
    for mod in sorted(by_module_class):
        md.append(f"### {mod}")
        md.append("")
        for c, n in sorted(by_module_class[mod].items()):
            md.append(f"- {c}: {n}")
        md.append("")
    args.out_md.parent.mkdir(parents=True, exist_ok=True)
    args.out_md.write_text("\n".join(md) + "\n")

    print(json.dumps(dict(by_class), indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())