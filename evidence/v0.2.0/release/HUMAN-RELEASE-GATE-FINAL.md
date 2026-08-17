# MGK v0.2.0 FINAL CANDIDATE — HUMAN RELEASE GATE (FINAL)

This report supersedes `evidence/v0.2.0/release/HUMAN-RELEASE-GATE.md` (pre-closure).
It is bound to the exact final candidate commit/tree below.

## Final state

| Field | Value |
|---|---|
| FUNCTIONAL | TRUE |
| BRANCH | `mgk-autopilot/v0.2.0-functional-runtime` |
| FINAL_COMMIT_SHA | `1327e5e85a44b3a917a0472b7de2e6a202326c8b` |
| FINAL_TREE_SHA | `716527089f40ad881520d3944c01b238d8d3e862` |
| VERSION | 0.2.0 |
| VERSIONED_WORKTREE_CLEAN | TRUE |
| ROOT_OF_TRUST | PASS |
| REGRESSION | PASS — 363 tests |
| MUTATION_GATE | PASS |
| MUTATION_EVIDENCE_MODE | SOURCE_EQUIVALENCE |
| MUTATION_SCORE | 0.905072 |
| KILLED | 1945 |
| SURVIVED_KILLABLE | 204 |
| EQUIVALENT_PROVEN | 40 |
| INDETERMINATE | 0 |
| CLEAN_INSTALL | PASS |
| REPRODUCIBILITY | PASS |
| SECRET_SCAN | PASS |
| BROWSER_API_CLI_ACCEPTANCE | PASS |
| INDEPENDENT_EXAM | PASS |

## Adversarial counters (within the tested corpus)

| Metric | Value |
|---|---|
| KNOWN_ORIGINAL_CODE_SECURITY_BYPASSES | 2 identified + remediated in red-team phase (cross-origin CSRF; silent evidence-drop on ledger corruption). No open bypasses. Plus 1 functional defect corrected (O_WRONLY->O_RDWR). |
| H14_FORBIDDEN_EXECUTIONS | 0 |
| FORGERY_SUCCESSES | 0 |
| REPLAY_SUCCESSES | 0 |
| SCOPE_ESCALATIONS | 0 |
| PAYLOAD_BINDING_BYPASSES | 0 |
| HUMAN_GATE_BYPASSES | 0 |
| SANDBOX_ESCAPES | 0 |
| FAIL_OPEN_EVENTS | 0 |

## Evidence corrections

1. `mutation-v2-classification.md` corrected: gate measured a tree containing the uncommitted
   O_WRONLY->O_RDWR change vs HEAD (was stated as "no source changes").
2. `mutation-v2-findings.json` preserved as historical observation; final `__init__.py` hash
   recorded in evidence-reconciliation.
3. Pre-closure `HUMAN-RELEASE-GATE.md` superseded by this report; preserved.

## Known limitations

1. 9 FS_PATH_CASE_ONLY EQUIVALENT_PROVEN mutants are equivalent only on case-insensitive
   filesystems; worst case if all 9 were counted killable: 1945/2158 = 0.9013 >= 0.90.
2. Browser (playwright) acceptance was recorded in the completed pipeline and not re-executed
   in closure; web behavior re-verified via scenarios A-J and red-team on the FINAL tree.
3. Verification covers the documented threat model and tested corpus; no claim of universal
   proof.
4. Root of Trust anchors protected paths; candidate source is not root-anchored.

## Decision

- TECHNICAL_CANDIDATE_READY: **TRUE**
- RELEASE_AUTHORIZED: **FALSE**
- MERGE_AUTHORIZED: **FALSE**
- TAG_AUTHORIZED: **FALSE**
- PUBLISH_AUTHORIZED: **FALSE**
- NEXT_REQUIRED_ACTION: **HUMAN_RELEASE_DECISION**

The autonomous pipeline stops here. No merge, tag, publish, or push to main has been performed.