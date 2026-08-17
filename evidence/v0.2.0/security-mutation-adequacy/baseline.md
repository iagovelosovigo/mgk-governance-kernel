# MGK v0.2.0 — Security Mutation Adequacy: Baseline

- Date: 2026-08-17
- Hardening branch: `mgk-autopilot/v0.2.0-security-mutation-adequacy`
  (created from the exact validated baseline commit)
- BASELINE_COMMIT: `1327e5e85a44b3a917a0472b7de2e6a202326c8b`
- BASELINE_TREE: `716527089f40ad881520d3944c01b238d8d3e862`
- BASELINE_VERSION: 0.2.0
- Worktree clean at branch creation: TRUE

## Baseline results (already validated)

| Metric | Value |
|---|---|
| TEST_COUNT | 363 |
| MUTATION_SCORE | 0.905072 |
| KILLED | 1945 |
| EVALUABLE | 2149 |
| SURVIVED_KILLABLE | 204 |
| EQUIVALENT_PROVEN | 40 |
| INDETERMINATE | 0 |
| MUTATION_SOURCE_EQUIVALENCE | PASS |
| ROOT_OF_TRUST | PASS |
| SECRET_SCAN | PASS |
| CLEAN_INSTALL | PASS |
| REPRODUCIBILITY | PASS |
| INDEPENDENT_EXAM | PASS |
| TECHNICAL_CANDIDATE_READY | TRUE |
| RELEASE_AUTHORIZED | FALSE |

## Objective of this phase

Harden the mutation-security methodology: (A) global mutation quality >= 0.90 remains,
(B) a NEW security mutation adequacy condition is added: security-sensitive survivors are
deterministically enumerated, classified, and every HIGH/CRITICAL weakening or reproducible
authority bypass is resolved, or the gate FAILS. Then re-deliver a functional MGK v0.2.0
candidate (version remains 0.2.0).