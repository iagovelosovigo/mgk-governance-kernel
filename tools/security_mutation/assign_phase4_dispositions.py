#!/usr/bin/env python3
"""Phase 4: attach deterministic phase4 dispositions to HIGH/CRITICAL survivors.

For every SURVIVED_KILLABLE mutant whose security class is HIGH/CRITICAL
(SECURITY_BYPASS, PERMISSION_WEAKENING, INTEGRITY_WEAKENING), this tool resolves
the disposition from a reference classification that already carries
phase4_disposition + phase4_evidence (e.g. the frozen v0.2.0 security-adequacy
evidence). A disposition is copied ONLY when the mutant diff is byte-identical
between the current classification and the reference, so the resolution is
mechanically verifiable and fails closed otherwise.

Mutants that no longer survive (killed by newly added discriminating tests) are
absent from the survivor set and therefore not classified here; their killing
test evidence lives in phase4-discriminating-test-verification.json.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

HIGH_CRITICAL = ("SECURITY_BYPASS", "PERMISSION_WEAKENING", "INTEGRITY_WEAKENING")
RESOLVED = ("KILLED", "EQUIVALENT_PROVEN", "TEST_GAP_ONLY", "AVAILABILITY_ONLY")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--classification", type=Path, required=True, help="current sensitive-survivor-classification.json")
    parser.add_argument("--reference", type=Path, required=True, help="reference classification carrying phase4_disposition/phase4_evidence")
    parser.add_argument("--out-json", type=Path, required=True)
    parser.add_argument("--out-md", type=Path, required=True)
    args = parser.parse_args()

    current = json.loads(args.classification.read_text())
    reference = json.loads(args.reference.read_text())
    ref_by_id = {m["id"]: m for m in reference["mutants"]}

    applied = 0
    missing = []
    mismatched = []
    for m in current["mutants"]:
        if m["classification"] != "SURVIVED_KILLABLE" or m["security_class"] not in HIGH_CRITICAL:
            m["phase4_disposition"] = "NOT_TARGET"
            m["phase4_evidence"] = "not a HIGH/CRITICAL target; no disposition required"
            continue
        ref = ref_by_id.get(m["id"])
        if ref is None:
            missing.append(m["id"])
            continue
        if ref.get("diff") != m.get("diff"):
            mismatched.append(m["id"])
            continue
        disp = ref.get("phase4_disposition")
        evid = ref.get("phase4_evidence")
        if disp not in RESOLVED:
            missing.append(f"{m['id']} (reference disposition {disp!r} not in {RESOLVED})")
            continue
        m["phase4_disposition"] = disp
        m["phase4_evidence"] = f"carried from v0.2.0 security-mutation-adequacy evidence (diff-identical mutant {m['id']}): {evid}"
        applied += 1

    if missing or mismatched:
        print("FAIL_CLOSED: unresolved targets")
        print("  missing:", missing)
        print("  diff mismatches:", mismatched)
        return 2

    from collections import Counter

    by_disp = Counter(m.get("phase4_disposition") for m in current["mutants"])
    doc = {
        "schema_version": "mgk.security-mutation-adequacy.v1",
        "kind": "sensitive-survivor-classification",
        "source": str(args.classification),
        "disposition_reference": str(args.reference),
        "disposition_rule": "copy phase4_disposition/phase4_evidence from reference only when mutant id + diff are identical",
        "counts_by_class": dict(Counter(m["security_class"] for m in current["mutants"])),
        "phase4_disposition_counts": dict(by_disp),
        "phase4_applied": applied,
        "mutants": current["mutants"],
    }
    payload = json.dumps(doc, indent=1)
    args.out_json.parent.mkdir(parents=True, exist_ok=True)
    args.out_json.write_text(payload + "\n")
    sha = hashlib.sha256(args.out_json.read_bytes()).hexdigest()
    args.out_json.with_name(args.out_json.name + ".sha256").write_text(sha + "\n")

    md = [
        "# Sensitive Survivor Security Classification (with phase 4 dispositions)",
        "",
        f"- source: `{args.classification}`",
        f"- disposition reference: `{args.reference}`",
        f"- phase4 dispositions applied: **{applied}**",
        "- SHA-256: `%s`" % sha,
        "",
        "## Counts by security class",
        "",
        "| class | count |",
        "|---|---|",
    ]
    for c, n in sorted(doc["counts_by_class"].items()):
        md.append(f"| {c} | {n} |")
    md.append("")
    md.append("## Counts by phase4 disposition")
    md.append("")
    for d, n in sorted(by_disp.items()):
        md.append(f"- {d}: {n}")
    md.append("")
    for m in current["mutants"]:
        if m.get("phase4_disposition") == "NOT_TARGET":
            continue
        md.append(f"### {m['id']}")
        md.append("")
        md.append(f"- module: `{m['module']}`  function: `{m['function']}`")
        md.append(f"- security class: `{m['security_class']}`  family: `{m.get('family')}`")
        md.append(f"- phase4 disposition: `{m['phase4_disposition']}`")
        md.append("")
        md.append(m.get("phase4_evidence", ""))
        md.append("")
    args.out_md.parent.mkdir(parents=True, exist_ok=True)
    args.out_md.write_text("\n".join(md) + "\n")

    print(json.dumps(dict(by_disp), indent=1))
    print(f"PHASE4_APPLIED={applied} MISSING={len(missing)} MISMATCHED={len(mismatched)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())