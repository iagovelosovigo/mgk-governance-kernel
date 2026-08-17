# HUMAN RELEASE GATE — FINAL (v0.2.0 Security-Mutation-Adequacy Campaign)

Date: 2026-08-17
Branch: `mgk-autopilot/v0.2.0-security-mutation-adequacy`
Final commit: `6074b4a2865b092181d88dc2582820f991bd715a`
Final tree: `309dcd42a677e2a461335bfe5c29024b3b11b1aa`
Worktree: clean.

## Gate summary

| Objective | Threshold | Result |
|---|---|---|
| GLOBAL_MUTATION_SCORE (phase-8 fresh, full population) | >= 0.90 | **0.915510 — PASS** |
| SECURITY_MUTATION_ADEQUACY | PASS | **PASS** |
| UNRESOLVED_HIGH / UNRESOLVED_CRITICAL | 0 | **0 / 0** |
| SECURITY_SENSITIVE_INDETERMINATE | 0 | **0** |
| FINAL_CODE_REPRODUCIBLE_SECURITY_BYPASSES | 0 | **0** |

Population: 3314 total, 3034 killed, 280 survived, 0 timeout.

## Campaign evidence (all phases verified)

| Phase | Evidence | Result |
|---|---|---|
| 4 | Sensitive-survivor disposition (93 HIGH/CRITICAL): 59 KILLED, 32 EQUIVALENT_PROVEN, 1 TEST_GAP_ONLY, 1 AVAILABILITY_ONLY | UNRESOLVED = 0 |
| 4 | 43 discriminating tests (permanent, in `tests/test_mutation_v3_security.py`) | 408-test suite |
| 6 | Source audit | 0 hardening findings |
| 7 | Functional E2E | PASS |
| 8 | Fresh full-population run on post-fix code (population-fresh.json + 7-mutant EQUIVALENT_PROVEN addendum) | 0.915510 |
| 9 | Adversarial red-team, 33 probes | 33/33 PASS |
| 10 | Clean install A/B | 407/407/407, identical trees |
| 11 | Secrets/root-of-trust + permission hardening (0700 dirs, 0600 sqlite) | PASS |
| 12 | Independent verification exam (recomputed from raw evidence) | all claims verified |
| 13 | Freeze + Ed25519 signature (27 files) | signature valid |
| 14–15 | Delivery package (wheel+sdist) + smoke | PASS, 408 tests from installed wheel |

Regression suite: **408 passed** (source tree and installed wheel).

## Known limitations

- `FS_PATH_CASE_ONLY` (9) EQUIVALENT_PROVEN mutants are equivalent only on
  case-insensitive filesystems (macOS APFS); on case-sensitive filesystems
  they would be killable. Even counting all 9 as killable, the score remains
  >= 0.90.
- The freeze signature's private key is ephemeral (generated at freeze time,
  never persisted); the public key and signature are embedded in the freeze
  artifact, so the signature is independently re-verifiable.
- Evidence covers the documented threat model and tested corpus; it does not
  claim universal security proof.
- Authority keys are generated at runtime per workspace; no committed key
  material.

## Release authorization

Per campaign directives, the final release decision is **reserved for a human**.
This report closes the automated pipeline; release authorization remains
pending.

```
NEXT_REQUIRED_ACTION=HUMAN_RELEASE_DECISION
RELEASE_AUTHORIZED=FALSE
STOP_HERE=TRUE
```