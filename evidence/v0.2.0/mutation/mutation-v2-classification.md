# Mutation Gate v2 — Classification (v0.2.0 Functional Governance Runtime)

- Branch: `mgk-autopilot/v0.2.0-functional-runtime`
- Date: 2026-08-17
- Population: mutmut 3.3.1 over `src/mgk` on a disposable copy
  (`mgk-verify/mutmut-v2`) that is byte-identical (sha256) to the repo working
  tree for every tested source and test file.
- CORRECTION (independent exam, 2026-08-17): the working tree measured by this
  gate contains one uncommitted functional source change vs HEAD (edd3ea6):
  `src/mgk/resource.py` `write_bound` present-target open flags
  `os.O_WRONLY` -> `os.O_RDWR` (mtime 01:51, predates the run-5 result dump
  02:59). The `O_RDWR` flag is required for the present-target branch, which
  reads the descriptor to verify `pre_sha256`/`pre_size` before truncate
  (`O_WRONLY` would raise EBADF on that read). The gate measured the tree as-is,
  so the result below is valid for the current working tree; the statement
  "only tests were strengthened" applies to the run-4 -> run-5 delta and NOT to
  the change since HEAD. No other source changes exist vs HEAD (all remaining
  uncommitted edits are tests).
- Test suite: 363 tests (repo suite, includes the strengthened
  `test_mutation_v2_*` files).
- Run: `mutmut run --max-children 8` (6.06 mutations/second), result dump
  `mututation-v2-results.txt`.

## Exact counts by category

| Category | Count | Definition (MGK-MUTATION-GATE-V2) |
|---|---|---|
| KILLED | 1945 | mutation changes behavior; a covering test fails |
| SURVIVED_KILLABLE | 204 | mutation changes observable behavior; no current test catches it |
| EQUIVALENT_PROVEN | 40 | provably no behavioral difference (runtime-probe evidence) |
| INVALID_MUTANT | 0 | none: all 2189 mutations applied and ran |
| UNREACHABLE_PROVEN | 0 | none classified |
| INDETERMINATE | 0 | none: every mutant evaluated |

**MUTATION_SCORE_V2 = KILLED / (KILLED + SURVIVED_KILLABLE) = 1945 / 2149 = 90.507%** (threshold 90.0%)

**VERDICT: PASS** (recorded in `mutation-v2-gate-report.json`)

## By module (KILLED / SURVIVED_KILLABLE / EQUIVALENT_PROVEN)

| Module | KILLED | SURVIVED_KILLABLE | EQUIVALENT_PROVEN |
|---|---|---|---|
| authority | 262 | 4 | 0 |
| cli | 267 | 94 | 9 |
| crypto | 102 | 0 | 5 |
| executor | 269 | 12 | 0 |
| resource | 653 | 94 | 26 |
| verifier | 392 | 0 | 0 |

## Surviving killable mutants by function

| Function | Count | Reason |
|---|---|---|
| cli.x_h14_smoke | 46 | frozen smoke script; every output-affecting mutation is provably inert or crash-caught to the same result |
| cli.x_main | 48 | argparse defaults/`--workdir` re-enforced by runtime_main (equivalent double-enforcement) and never-taken branches |
| resource.create_bound | 32 | unreachable guards (post_size ≤ 8 MiB cap enforced at bind time; st_size always == len(data)) |
| resource.write_bound | 35 | unreachable/race-gated branches and inert flag getattr defaults |
| resource.append_bound | 19 | unreachable short-write/verification branches; inert flag defaults |
| executor.execute | 12 | message-only mutations swallowed by deny-path (observable surface unchanged) |
| resource._open_parent | 3 | inert flag getattr defaults |
| resource.remove_created | 4 | equivalent guard outcomes |
| resource.bind_absent | 1 | follow_symlinks default (equivalent) |
| authority._bind_resource | 4 | size-limit raise unreachable via issue() (canonical 256 KiB cap rejects earlier) |

## Honesty note (differs from v0.1.0)

This gate is reached without reclassifying killable survivors as equivalent.
`EQUIVALENT_PROVEN` (40) are only mutations whose mutated body is byte-identical
to the original after the rename (mutmut duplicates) or whose behavior is
provably identical (e.g. `rstrip(b"=")` vs `rstrip(b"XX=XX")` stripping the
same character class, `follow_symlinks=None` default, `getattr` on an attribute
that always exists, `"ASCII"` codec alias). The remaining 204 survivors are
honestly counted as killable; the score clears the 90% bar above the survivors.

## Coverage of the kill batch (run 4 → run 5)

New/strengthened tests added this cycle (all pass on original source):
- `test_mutation_v2_resource.py`: write-to-directory, broken-symlink,
  8 MiB exact-limit boundaries (bind/append/write/create), over-limit append
  result, present-empty-truncate, target-deleted, missing-midwalk, rollback
  refusal on directory/changed-content targets.
- `test_mutation_v2_verifier.py`: direct `_validate_payload` calls with
  re-digested mutated payloads (write/append binding sets and states,
  pre-state, scope, read_record), and clock-skew boundary `verify`.
- `test_mutation_v2_executor.py`: sandbox read execute, denial-after-bind
  keeps capability_id, maximum-TTL issuance.
- `test_mutation_v2_crypto.py`: trailing-alphabet-byte b64u encoding.
- `test_mutation_v2_cli.py`: exact `start` parser/usage/`--workdir` errors.

Kills attributable to this batch: +61 (1884 → 1945).
