# MGK v0.2.0 — Pre-Closure State Snapshot

Recorded: 2026-08-17 (before any closure commit)

## Git state

- Branch: `mgk-autopilot/v0.2.0-functional-runtime`
- HEAD: `5f069ada2174ef3375bf90b66fa338d440121238`
- HEAD tree: `c53b9257034b64d60097f5a7c4e07c00de2d5894`
- Staged: none
- Unstaged: `src/mgk/resource.py` (1 functional line) + 5 test files
- Untracked: 11 evidence files (mutation/install/independent-exam/release) + 2 new test files
  (`test_mutation_v2_schema_errors.py`, `test_mutation_v2_verifier.py`)

## Known O_WRONLY -> O_RDWR change

- File: `src/mgk/resource.py`, function `ResourceGuard.write_bound` (present-target branch)
- Diff: `flags = os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0)` -> `os.O_RDWR | ...`
- Why required: present-target branch reads the descriptor (`_read_descriptor`) to verify
  `pre_sha256`/`pre_size` before `ftruncate`; `O_WRONLY` would raise EBADF on that read.
- mtime 01:51 predates the mutation result dump (02:59).
- `mutmut-v2/src/mgk/resource.py` sha256 == working tree `src/mgk/resource.py` (MATCH).
- Conclusion: the 363-pass suite and the 0.905072 mutation run both executed on the tree
  containing this change. It is a FUNCTIONAL_CHANGE_ALREADY_TESTED.

## Version declarations

| Location | Value | Class |
|---|---|---|
| pyproject.toml | version = "0.1.0" | CURRENT_SOFTWARE_VERSION -> 0.2.0 |
| src/mgk/__init__.py | `__version__ = "0.1.0"`, docstring "…v0.1.0 public API." | CURRENT_SOFTWARE_VERSION -> 0.2.0 |
| runtime/__init__.py | RUNTIME_VERSION = "0.2.0" | already current |
| runtime/web.py | server_version "MGK-Runtime/0.2.0", version field "0.2.0" | already current |
| runtime/workspace.py | manifest version "0.2.0" | already current |
| README-MGK.md | title "MUDA Governance Kernel v0.1.0" | DOCUMENTATION_CURRENT_VERSION -> 0.2.0 |
| NOTICE.md | "MGK v0.1.0 is an engineering implementation…" | AMBIGUOUS -> inspect semantics |
| contracts/*.yaml, tools/*.py | contract_id "MGK-v0.1.0-mutation-gate-2" | CONTRACT_OR_SCHEMA_VERSION -> preserve |

## Mutation-tested source population

- `paths_to_mutate = ["src/mgk"]`; mutant copy at `mgk-verify/mutmut-v2`.
- Modules WITH mutants: authority (266), cli (370), crypto (107), executor (281),
  resource (773), verifier (392).
- Modules with ZERO mutants: `__init__`, arrow, canonical, cha, clock, errors, feedback,
  ledger, models, saxp, state (copied into the source tree but contribute 0 mutants).
- sha256 of mutation copy vs working tree: MATCH for all 7 checked src files including
  `__init__.py`.
- Therefore a pure version change in `src/mgk/__init__.py` (0 mutants in population) does
  not invalidate the prior mutation result, provided the 6 mutant-bearing modules remain
  byte-identical in the final candidate (re-verified in Phase 6).

## Completed technical results carried forward

363 passed; MUTATION_SCORE_V2 0.905072 (KILLED 1945, EVALUABLE 2149,
SURVIVED_KILLABLE 204, EQUIVALENT_PROVEN 40, INDETERMINATE 0); clean install A/B PASS;
reproducibility PASS; secret scan PASS; independent exam VERIFIED; RELEASE_AUTHORIZED FALSE.