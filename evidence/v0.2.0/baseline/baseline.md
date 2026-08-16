# MGK v0.2.0 — Baseline Snapshot

- **Date**: 2026-08-16T22:33:00Z
- **Generator**: mgk-autopilot/v0.2.0-functional-runtime
- **Machine-readable**: `baseline.json`

## v0.1.0 identity (authoritative, git-derived)

- Tag `v0.1.0` -> commit `130606b3f403e22e5c9b85a467a3012fe83da381` (merge of PR #7)
- Tree `70fcc64e27d4db541d7f874fba038689e7eb8373`
- Prompt-stated tree `70fcc642e...` is a transcription error; git-derived value used everywhere.

## Root of Trust

- `contracts/ROOT_MANIFEST.sha256` anchor = `4c309aad3d8983dcb930eb6a4808df0bb93fdd04ce2bebd191fc7b624f2e480f` (matches manifest self-hash)
- `orchestrator/tcb/trust.py` with `MGK_ROOT_MANIFEST_SHA256=4c309aad...` -> **"Protected tree verified."** (27 protected paths)

## v0.2.0 branch

- `mgk-autopilot/v0.2.0-functional-runtime` created from main @ `130606b...` (no tracked modifications; only untracked caches present).

## Invariants preserved (no weakening)

- H14: "Compromised Intelligence does not imply Compromised Authority (I != A)".
- Fail-closed: any INDETERMINATE / unexpected / integrity failure -> DENY with no side effect.
- Mutation Gate v2 threshold >= 0.90, INDETERMINATE == 0, EVALUABLE > 0.
- v0.1.0 tests, contracts, independent_exam, and Root of Trust remain unchanged by v0.2.0.

## Status: BASELINE_VERIFIED