# MGK v0.2.0 — FINAL Independent Examination Findings

Examiner: independent/adversarial, no prior context on evidence production.
Date: 2026-08-17. All claims verified mechanically (read-only). No source, test, or existing evidence was modified. Evidence is bound to the working tree at `/Users/iagoveloso/mgk-governance-kernel` (branch `mgk-autopilot/v0.2.0-functional-runtime`, HEAD `ee606d6`).

---

## 1. Identity — VERIFIED

| Claim | Recomputed value | Match |
|---|---|---|
| Commit exists | `git rev-parse 1327e5e85a44b3a917a0472b7de2e6a202326c8b` → `1327e5e85a44b3a917a0472b7de2e6a202326c8b` | YES |
| On branch | `git branch --contains` → `* mgk-autopilot/v0.2.0-functional-runtime` | YES |
| Tree SHA | `git rev-parse 1327e5e^{tree}` → `716527089f40ad881520d3944c01b238d8d3e862` | YES |
| Parent SHA | `git rev-parse 1327e5e^` → `bd36870e03f337ff567dd285e9c83685d650d3e9` | YES |
| Is version-bump commit | `git show 1327e5e --stat` → "chore: set MGK candidate version to 0.2.0", 4 files, 5 insertions/5 deletions | YES |
| Diff limited to claimed files | `git show 1327e5e` → only `pyproject.toml`, `src/mgk/__init__.py`, `README-MGK.md`, `NOTICE.md`; each changed 0.1.0→0.2.0 (2 lines each; `__init__.py` also docstring). No other paths touched | YES |
| Worktree clean | `git status --short` → **NOT clean**: 6 untracked files under `evidence/v0.2.0/release/` (see Discrepancy 1) | NO (see note) |

Commit contents confirmed: only the 4 metadata/version files; `src/`, `tests/`, `runtime/`, `pyproject.toml` production content identical between `1327e5e` and HEAD (`git rev-parse HEAD:src/mgk/__init__.py` == `1327e5e:src/mgk/__init__.py` == `58f8606…`; `git diff 1327e5e HEAD -- src/ tests/ runtime/ pyproject.toml requirements.lock` empty). Post-FINAL commits (`ee606d6`) add evidence only.

## 2. Version 0.2.0 — VERIFIED

- `python3 -c "import tomllib; …['project']['version']"` → **0.2.0**
- `src/mgk/__init__.py`: docstring `"""MUDA Governance Kernel v0.2.0 public API."""`, `__version__ = "0.2.0"` (line 42)
- `runtime/__init__.py`: `RUNTIME_VERSION = "0.2.0"` (line 10)
- `runtime/web.py`: `server_version = "MGK-Runtime/0.2.0"` (line 44), `{"status":"ok","version":"0.2.0"}` (line 111)
- Live import: `mgk.__version__` → 0.2.0, `runtime.RUNTIME_VERSION` → 0.2.0

## 3. Root of Trust — VERIFIED

Command:
```
MGK_ROOT_MANIFEST_SHA256=4c309aad3d8983dcb930eb6a4808df0bb93fdd04ce2bebd191fc7b624f2e480f \
PYTHONPATH=/Users/iagoveloso/mgk-governance-kernel/orchestrator/tcb \
/var/folders/bf/7f75557n44s0d89v_dx0l7cr0000gn/T/opencode/mgk-verify/venv/bin/python orchestrator/tcb/trust.py
```
Output: **`Protected tree verified.`**

## 4. Regression >= 363 — VERIFIED

```
cd /Users/iagoveloso/mgk-governance-kernel
PYTHONPATH=src:. <venv>/bin/python -m pytest tests -q -p no:cacheprovider
```
Result: **`363 passed in 4.64s`** (exactly 363).

## 5. Mutation evidence binding (SOURCE_EQUIVALENCE) — VERIFIED

**Byte-identity of all `src/mgk/*.py`** (17 files, mutmut-v2 source vs FINAL):
- 16 files byte-identical (`arrow, authority, canonical, cha, cli, clock, crypto, errors, executor, feedback, ledger, models, resource, saxp, state, verifier`).
- **Only difference: `src/mgk/__init__.py`** — `diff` shows exactly 2 lines changed: docstring `v0.1.0`→`v0.2.0` (line 1) and `__version__ = "0.1.0"`→`"0.2.0"` (line 42). Nothing else.

**Per-module mutant counts** (from `mutation-v2-classification.json`, recomputed over the 2189-mutant list):
- authority = 266, cli = 370, crypto = 107, executor = 281, resource = 773, verifier = 392 (sum = 2189)
- `__init__` module: **0 mutants** (not present in the list). Claimed → confirmed.

**Gate math**: `MUTATION_SCORE = KILLED/(KILLED+SURVIVED_KILLABLE) = 1945/2149 = 0.905072126… ≥ 0.90` → PASS. `mutation-v2-gate-report.json` states `MUTATION_SCORE_V2: 0.905072`, `EVALUABLE: 2149`, `verdict: PASS`, `threshold: 0.9` → matches recomputation exactly.

**Counts** (recomputed from the classification list):
- KILLED = 1945, SURVIVED_KILLABLE = 204, EQUIVALENT_PROVEN = 40, INDETERMINATE = 0
- run_status: killed = 1945, survived = 244 (204 + 40 reclassified to EQUIVALENT_PROVEN)
- timeouts = 0, no-tests = 0
- survivors reclassified to KILLED = 0 (all 1945 KILLED have `run_status: "killed"`, justification "mutmut reported killed")
- Sum check: 1945+204+40 = 2189 = 266+370+107+281+773+392 ✓

## 6. Clean install A/B + reproducibility — VERIFIED

`/var/folders/bf/7f75557n44s0d89v_dx0l7cr0000gn/T/opencode/mgk-verify/ab-final` contains `repo/`, `venv-a/`, `venv-b/`.

- Installed dist version: `venv-a` → **0.2.0**, `venv-b` → **0.2.0** (`importlib.metadata.version('muda-governance-kernel')`)
- Suite in `ab-final/repo`: **venv-a → 363 passed (4.49s)**, **venv-b → 363 passed (4.82s)**
- Installed site-packages: `mgk` = 17 `.py` files in both; sha256-diff `A` vs `B` → **MGK IDENTICAL**
- `runtime` = 10 `.py` files (9 top-level + `sandbox/__init__.py`); sha256-diff over all → **RUNTIME FULL IDENTICAL**
- Installed-only: `ab-final/repo/runtime` moved aside, `venv-a` suite → **363 passed (4.29s)** from site-packages; runtime restored afterwards.

## 7. Secret scan — VERIFIED (no findings)

On git-tracked content, excluding `evidence/redteam`, `evidence/independent_exam`, `evidence/v0.2.0/independent-exam`:
- `git ls-files` filtered for `PRIVATE KEY`, `AKIA[0-9A-Z]{16}`, `ghp_[A-Za-z0-9]{36}`, `sk-[A-Za-z0-9]{20,}` → **no matches**
- `git ls-files` filtered for `*.pem`, `*.key`, `*.env` → **0 tracked files**
- `git grep` for credential assignments (`password|passwd|secret|token|api_key` = literal) → **no matches** after excluding test/placeholder/example patterns
- `git grep -l 'BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY'` → **no matches**

## 8. Authority separation / fail-closed / no unauthorized side effect — VERIFIED (within documented corpus)

- `evidence/v0.2.0/redteam/redteam.json`: `all_pass = True`, 15 findings (R1–R14 + R1-sameorigin) all `status: PASS`; `post_attack_doctor.status: PASS`; `post_attack_test.results.h14_proposal_is_not_authority: true`, `status: PASS`.
- `evidence/v0.2.0/integration/scenarios.json`: `all_passed = True`, 10 scenarios A–J, `doctor.status: PASS`.
- H14 in suite: `tests/test_h14.py` — 4 tests (forbidden capability issue=0, no forge/mutate, `h14_forbidden_executions == 0` across attack set, exception is fail-closed). `pytest tests/test_h14.py` → **4 passed**.
- Live re-run: `PYTHONPATH=src:. <venv>/bin/python tools/redteam_v2.py --out <temp>` → all 15 findings PASS, `all pass: True` (R6-nonce-replay PASS, R11-unknown-action PASS, R12-deny-mode PASS, etc.).
- CLI smoke: `python -m mgk.cli h14-smoke` → `h14_forbidden_executions: 0`, `result: PASS`.

Scope statement: this is evidence within the documented test corpus (tests + redteam + scenarios), not a universal proof. The live red-team run re-confirmed the API-level behavior on the FINAL tree.

## 9. Evidence consistency — VERIFIED

- `evidence/v0.2.0/release/candidate-identity.json`: `version: 0.2.0`, `branch: mgk-autopilot/v0.2.0-functional-runtime`, `commit_sha: 1327e5e85a44b3a917a0472b7de2e6a202326c8b`, `tree_sha: 716527089f40ad881520d3944c01b238d8d3e862`, `parent_commits: [bd36870e03f337ff567dd285e9c83685d650d3e9]` → all match recomputation.
- `evidence-reconciliation.md` records: (a) `__init__.py` hash difference — mutation-tested `e3c9742…` vs FINAL `4fc01d49…` (version bump only) — both hashes confirmed by direct sha256; (b) the `O_WRONLY→O_RDWR` correction to the "no source changes" claim in `mutation-v2-classification.md`. Both dispositions verified as present and accurate.
- `mutation-source-equivalence.md`: explicitly states `MUTATION_SOURCE_EQUIVALENCE: PASS` and documents that `__init__.py` contributes 0 mutants; the 6 mutant-bearing modules are byte-identical (confirmed independently).
- Global grep over FINAL evidence for commit/tree/version strings: all `1327e5e`/`71652708`/`bd36870` references occur only in the identity/reconciliation/revalidation/equivalent evidence, and all agree. No FINAL evidence file asserts a different commit/tree/version. Historical identifiers preserved (contract_id `MGK-v0.1.0-mutation-gate-2`, tag `v0.1.0`, README.md `v0.1.0`) are consistent with the reconciliation's stated policy.

---

## Discrepancies / notes

1. **Worktree not fully clean (minor, non-source).** `git status --short` reports 6 untracked files, all under `evidence/v0.2.0/release/`: `candidate-identity.json`, `candidate-identity.md`, `evidence-reconciliation.json`, `evidence-reconciliation.md`, `final-candidate-revalidation.md`, `mutation-source-equivalence.md`. These are the newly generated FINAL evidence artifacts that have not yet been committed. `candidate-identity.json` states `versioned_worktree_clean: true` and `untracked_ephemeral_files: []` — consistent with the state at the FINAL commit, but the on-disk worktree currently contains these untracked evidence files. This does not affect source/tree integrity: tracked content equals the FINAL tree (verified), and the untracked files are evidence documentation only.
2. **`HUMAN-RELEASE-GATE-FINAL` not present on disk.** `evidence-reconciliation.md`/`.json` state the pre-closure `HUMAN-RELEASE-GATE.md` is "Superseded by HUMAN-RELEASE-GATE-FINAL", but no `HUMAN-RELEASE-GATE-FINAL.*` file exists in the repository (tracked or untracked). The supersession note is aspirational/forward-looking, not a wrong-identity claim. Flagged for completeness; does not affect the FINAL candidate identity.
3. **Verdict scope.** Item 8 is verified as coverage of the *documented* test corpus (363 tests incl. H14, 15 red-team findings, 10 scenarios, live red-team re-run). This is not a universal security proof.

---

## Final verdict

**Core claim** — "NO GOVERNED SIDE EFFECT CAN OCCUR WITHOUT VALID, SCOPED, PAYLOAD/REQUEST-BOUND, NON-REPLAYABLE AUTHORITY":

**SUPPORTED within the documented threat model and tested corpus** (tested, not universal).

Evidence chain supporting it, all independently reconfirmed:
- Root of Trust manifest verifies (`Protected tree verified.`) with the claimed anchor.
- 363/363 regression tests pass on the FINAL tree; fail-closed exception behavior, zero forbidden executions across the H14 attack set (`tests/test_h14.py`), zero capability issuance for out-of-scope/deputy/principal-spoof requests.
- Red-team evidence (all_pass true, 15/15) and live re-run all PASS, including nonce-replay (R6), flight tamper (R7), deny-mode (R12), malformed body (R14); post-attack state doctor PASS and `h14_proposal_is_not_authority` true confirm no unauthorized side effect persisted.
- Mutation evidence binds to the FINAL tree via SOURCE_EQUIVALENCE (6 mutant-bearing modules byte-identical; only non-behavioral version constants differ in `__init__.py`, which has 0 mutants); mutation score 0.905072 ≥ 0.90 recomputed exactly.
- Clean-install A/B: installed-only 363 passes in both fresh venvs; installed `mgk` (17 files) and `runtime` (10 files) byte-identical A vs B; installed version 0.2.0.

**Evidence consistency holds.** All FINAL evidence files agree on identity (1327e5e / 71652708… / 0.2.0 / parent bd36870…), mutation counts (1945/204/40/0, score 0.905072), test count (363), and install hashes. No FINAL evidence mis-states commit/tree/version. The two flagged notes (untracked release evidence files; HUMAN-RELEASE-GATE-FINAL absent) are documentation-state issues, not integrity or identity failures.
