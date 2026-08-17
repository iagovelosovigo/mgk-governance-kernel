#!/usr/bin/env python3
"""Deterministic extraction of SECURITY_SENSITIVE survivors.

Operates on the canonical full-population mutation classification (produced by
build_classification.py over the FULL src/mgk population with no do_not_mutate
exclusions). Selects exactly `classification == SURVIVED_KILLABLE`, keeps only
mutants whose module is in the normative security-sensitive population defined
by MGK-SECURITY-MUTATION-ADEQUACY-V1.yaml, and emits:

  sensitive-survivors.json
  sensitive-survivors.md
  sensitive-survivors.sha256

The selection, membership, ordering and integrity checks are fully mechanical:
no LLM inference decides population membership. The tool fails closed if the
population cannot be reconstructed deterministically.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

# Security-sensitive src/mgk population, normative from MGK-SECURITY-MUTATION-ADEQUACY-V1.yaml
# (security_sensitive_modules minus the runtime/* entries, which are not yet in the
# src/mgk mutation population; runtime adequacy is a separate Phase 8 work item).
SECURITY_SENSITIVE_MODULES = {
    "authority", "canonical", "crypto", "executor", "ledger", "models",
    "resource", "saxp", "state", "verifier",
}

REQUIRED_FIELDS = ("id", "module", "function", "mutant_index", "run_status", "classification")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--classification", type=Path, required=True, help="canonical full-population classification JSON")
    parser.add_argument("--out-json", type=Path, required=True)
    parser.add_argument("--out-md", type=Path, required=True)
    parser.add_argument("--out-sha", type=Path, required=False)
    args = parser.parse_args()

    classification = json.loads(args.classification.read_text())
    if not isinstance(classification, dict) or "mutants" not in classification:
        raise SystemExit("FAIL_CLOSED: classification is malformed (missing mutants list)")

    sensitive = set(SECURITY_SENSITIVE_MODULES)

    seen: set[str] = set()
    selected: list[dict] = []
    total_killable = 0
    non_sensitive = 0
    per_module: dict[str, int] = {}

    for rec in classification["mutants"]:
        if not isinstance(rec, dict):
            raise SystemExit("FAIL_CLOSED: malformed mutant record")
        missing = [f for f in REQUIRED_FIELDS if f not in rec or rec[f] in (None, "")]
        if missing:
            raise SystemExit(f"FAIL_CLOSED: mutant record missing {missing}: {rec.get('id', '?')}")
        if rec["classification"] != "SURVIVED_KILLABLE":
            continue
        total_killable += 1
        mid = rec["id"]
        if mid in seen:
            raise SystemExit(f"FAIL_CLOSED: duplicate mutant id {mid}")
        seen.add(mid)
        mod = rec["module"]
        if "." in mod or "/" in mod or not mod:
            raise SystemExit(f"FAIL_CLOSED: ambiguous source attribution for module {mod!r} in {mid}")
        if mod not in sensitive:
            non_sensitive += 1
            continue
        per_module[mod] = per_module.get(mod, 0) + 1
        selected.append(rec)

    selected.sort(key=lambda r: r["id"])
    rows = [
        {
            "id": r["id"],
            "module": r["module"],
            "function": r["function"],
            "mutant_index": r["mutant_index"],
            "run_status": r["run_status"],
            "classification": r["classification"],
            "family": r.get("family", []),
            "justification": r.get("justification", ""),
            "evidence": r.get("evidence", ""),
        }
        for r in selected
    ]

    doc = {
        "schema_version": "mgk.security-mutation-adequacy.v1",
        "kind": "sensitive-survivors",
        "source_classification": str(args.classification),
        "selection_rule": "classification == SURVIVED_KILLABLE AND module in security-sensitive population",
        "security_sensitive_modules": sorted(sensitive),
        "counts": {
            "TOTAL_SURVIVED_KILLABLE": total_killable,
            "SECURITY_SENSITIVE_SURVIVORS": len(rows),
            "NON_SECURITY_SURVIVORS": non_sensitive,
            "PER_MODULE_COUNTS": dict(sorted(per_module.items())),
        },
        "integrity": {
            "UNIQUE_IDS": len(seen),
            "DUPLICATES": 0,
            "JSON_MD_ID_EQUALITY": None,
        },
        "mutants": rows,
    }

    payload = json.dumps(doc, indent=1)
    args.out_json.parent.mkdir(parents=True, exist_ok=True)
    args.out_json.write_text(payload + "\n")
    sha = hashlib.sha256(args.out_json.read_bytes()).hexdigest()
    sha_path = args.out_sha or args.out_json.with_name(args.out_json.name + ".sha256")
    sha_path.write_text(sha + "\n")

    md_ids = [r["id"] for r in rows]
    json_ids = [r["id"] for r in rows]
    md = [
        "# Security-Sensitive Survivors (SURVIVED_KILLABLE)",
        "",
        f"- source classification: `{args.classification}`",
        f"- TOTAL_SURVIVED_KILLABLE: **{total_killable}**",
        f"- SECURITY_SENSITIVE_SURVIVORS: **{len(rows)}**",
        f"- NON_SECURITY_SURVIVORS: **{non_sensitive}**",
        "- UNIQUE_IDS: %d  DUPLICATES: 0" % len(seen),
        "- SHA-256: `%s`" % sha,
        "",
        "| module | survivors |",
        "|---|---|",
    ]
    for m in sorted(per_module):
        md.append(f"| {m} | {per_module[m]} |")
    md.append("")
    md.append("## Mutant records")
    for r in rows:
        md.append(f"### {r['id']}")
        md.append("")
        md.append(f"- module: `{r['module']}`")
        md.append(f"- function: `{r['function']}`")
        md.append(f"- mutant index: `{r['mutant_index']}`")
        md.append(f"- run status: `{r['run_status']}`")
        md.append(f"- classification: `{r['classification']}`")
        md.append(f"- family: `{', '.join(r['family'])}`")
        md.append("")
        md.append("```diff")
        md.append(r["evidence"])
        md.append("```")
        md.append("")
    args.out_md.parent.mkdir(parents=True, exist_ok=True)
    args.out_md.write_text("\n".join(md) + "\n")

    md_ids_from_file = []
    for line in args.out_md.read_text().splitlines():
        if line.startswith("### "):
            md_ids_from_file.append(line[4:].strip())
    if md_ids_from_file != json_ids:
        raise SystemExit("FAIL_CLOSED: JSON and Markdown mutant id sets diverge")
    doc["integrity"]["JSON_MD_ID_EQUALITY"] = True
    args.out_json.write_text(json.dumps(doc, indent=1) + "\n")

    print(json.dumps(doc["counts"], indent=1))
    print(json.dumps(doc["integrity"], indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())