#!/usr/bin/env python3
"""Calculate the MGK verdict from frozen criteria and observed evidence."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import sys
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(Path(__file__).resolve().parent))
from check_frozen import verify as verify_frozen

HEX64 = re.compile(r"^[0-9a-f]{64}$")


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def evaluate(
    acceptance: dict[str, Any],
    observations: dict[str, Any],
    artifact_root: Path | None,
) -> list[str]:
    failures = verify_frozen(ROOT)
    frozen_digest = digest(ROOT / "FROZEN.sha256")
    if observations.get("schema_version") != "mgk.observations.v1":
        failures.append("observations.schema_version")
    if observations.get("contract_sha256") != frozen_digest:
        failures.append("contract_sha256 does not bind the frozen exam")
    candidate = observations.get("candidate", {})
    if candidate.get("version") != "0.1.0":
        failures.append("candidate.version")
    for field in ("source_sha256", "commit_sha"):
        value = candidate.get(field)
        if not isinstance(value, str) or not re.fullmatch(
            r"[0-9a-f]{64}" if field == "source_sha256" else r"[0-9a-f]{40,64}",
            value,
        ):
            failures.append(f"candidate.{field}")

    observed_suites = observations.get("suites", {})
    for name, required in acceptance["required_suites"].items():
        actual = observed_suites.get(name)
        if not isinstance(actual, dict):
            failures.append(f"suite.{name}.missing")
            continue
        if not isinstance(actual.get("total"), int) or actual["total"] <= 0:
            failures.append(f"suite.{name}.total")
        for key, expected in required.items():
            if actual.get(key) != expected:
                failures.append(f"suite.{name}.{key}: {actual.get(key)!r} != {expected!r}")

    observed_metrics = observations.get("metrics", {})
    for name, expected in acceptance["required_metrics"].items():
        if observed_metrics.get(name) != expected:
            failures.append(f"metric.{name}: {observed_metrics.get(name)!r} != {expected!r}")

    observed_checks = observations.get("checks", {})
    for name, expected in acceptance["required_checks"].items():
        if observed_checks.get(name) != expected:
            failures.append(f"check.{name}: {observed_checks.get(name)!r} != {expected!r}")

    score = observations.get("mutation_score_percent")
    if not isinstance(score, (int, float)) or score < acceptance["minimum_mutation_score_percent"]:
        failures.append("mutation_score_percent")

    observed_clean = observations.get("clean_install", {})
    for label, expected in acceptance["clean_install"].items():
        if observed_clean.get(label) != expected:
            failures.append(f"clean_install.{label}")

    observed_repro = observations.get("reproducibility", {})
    for name, expected in acceptance["reproducibility"].items():
        if observed_repro.get(name) != expected:
            failures.append(f"reproducibility.{name}")

    observed_artifacts = observations.get("artifacts", {})
    generated = {
        "MGK-v0.1.0-FUNCTIONAL-VERDICT.json",
        "MGK-v0.1.0-FUNCTIONAL-VERDICT.md",
    }
    for name in acceptance["required_artifacts"]:
        if name in generated:
            continue
        claimed = observed_artifacts.get(name)
        if not isinstance(claimed, str) or not HEX64.fullmatch(claimed):
            failures.append(f"artifact.{name}.hash_missing")
            continue
        if artifact_root is None:
            failures.append(f"artifact.{name}.not_independently_verified")
            continue
        path = artifact_root / name
        if not path.is_file():
            failures.append(f"artifact.{name}.missing")
        elif digest(path) != claimed:
            failures.append(f"artifact.{name}.hash_mismatch")
    return sorted(set(failures))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--acceptance", type=Path, default=ROOT / "FUNCTIONAL-ACCEPTANCE.yaml")
    parser.add_argument("--observations", type=Path, required=True)
    parser.add_argument("--artifact-root", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()

    acceptance = load_json(args.acceptance)
    observations = load_json(args.observations)
    failures = evaluate(acceptance, observations, args.artifact_root)
    functional = not failures
    contract_sha = digest(ROOT / "FROZEN.sha256")
    verdict = {
        "schema_version": "mgk.functional-verdict.v1",
        "contract_id": acceptance["contract_id"],
        "contract_sha256": contract_sha,
        "candidate": observations.get("candidate", {}),
        "functional": functional,
        "verdict": "MGK v0.1.0 — FUNCTIONAL = TRUE" if functional else "FUNCTIONAL = FALSE",
        "evaluated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "failures": failures,
        "observations_sha256": digest(args.observations),
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(verdict, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    md_path = args.out.with_suffix(".md")
    lines = [
        "# MGK v0.1.0 — veredicto funcional",
        "",
        f"- Veredicto: **{verdict['verdict']}**",
        f"- Contrato: `{contract_sha}`",
        f"- Observaciones: `{verdict['observations_sha256']}`",
        "",
    ]
    if failures:
        lines.extend(["## Condiciones incumplidas", ""] + [f"- `{item}`" for item in failures])
    else:
        lines.append("Todos los criterios congelados fueron satisfechos.")
    md_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(verdict["verdict"])
    return 0 if functional else 1


if __name__ == "__main__":
    raise SystemExit(main())

