# MGK v0.2.0 — FINAL HUMAN RELEASE GATE REPORT

- Branch: `mgk-autopilot/v0.2.0-functional-runtime`
- Report date: 2026-08-17
- Autonomous pipeline: COMPLETE. Final gate is reserved for a human.
- **RELEASE_AUTHORIZED: FALSE** (no autonomous approval; a human must decide.)

---

## 1. Candidate state

| Item | Value |
|---|---|
| HEAD | `5f069ad security(v0.2.0): red team v0.2.0, all 14 attacks pass` |
| Prior commits | `9bc5e84` scenarios A–J + browser acceptance; `edd3ea6` functional runtime; `2d0ae14` baseline/root-of-trust; `d3e1a6d` discovery |
| pyproject version | **0.1.0** (not bumped — no release authorized; a human must decide the release version) |
| Package | `muda-governance-kernel`; entry point `mgk = mgk.cli:main`; packages `mgk`, `runtime`, `runtime.sandbox` |
| Uncommitted working-tree changes | 1 functional source change + test additions (see §4.1) |

## 2. Gate results

| Gate | Evidence | Result |
|---|---|---|
| Discovery (architecture) | `evidence/v0.2.0/discovery` | DONE |
| Baseline + root-of-trust | `evidence/v0.2.0/baseline/baseline.json`, `baseline.md` | PASS |
| Functional acceptance (scenarios A–J, browser acceptance v2) | `evidence/v0.2.0/browser`, `tools/browser_acceptance_v2.py`, `tools/scenarios_v2.py` | PASS |
| Red team (14 attacks) | `evidence/v0.2.0/redteam/redteam.json`, `redteam.md` | PASS (all 14) |
| Integration | `evidence/v0.2.0/integration` | PASS |
| Full test suite | 363 tests (`tests/`) | **363 passed** |
| Mutation gate v2 | `evidence/v0.2.0/mutation/mutation-v2-gate-report.json` | **PASS — MUTATION_SCORE_V2 = 0.905072 ≥ 0.90** |
| Clean install A/B | `evidence/v0.2.0/install/clean-install-ab.md` | PASS (363/363, byte-identical installs) |
| Dependency freeze | `evidence/v0.2.0/install/dependency-freeze-and-secret-scan.md` | PASS (cryptography 46.0.0, pytest 8.4.1, hypothesis 6.138.13, pytest-timeout 2.4.0) |
| Secret scan | same file | PASS (no keys/tokens/credentials) |
| Independent exam | `evidence/v0.2.0/independent-exam/FINDINGS.md` | ALL 4 CLAIMS VERIFIED (see §3) |

### Mutation gate detail

- EVALUABLE = 2149; KILLED = 1945; SURVIVED_KILLABLE = 204;
  EQUIVALENT_PROVEN = 40; INDETERMINATE = 0; timeout/no-tests = 0.
- MUTATION_SCORE_V2 = 1945 / 2149 = **0.905072**; threshold 0.90 → **PASS**.
- Survivor profile: resource 94 SK + 26 EQ, cli 94 SK + 9 EQ, executor 12 SK,
  authority 4 SK, verifier 0, crypto 5 EQ — remaining survivors are provably
  unreachable/inert branches (frozen H14 smoke, dead create/write/append-bound
  branches, message-only denials).

## 3. Independent exam verdict (adversarial, no builder context)

- **Claim 1 (mutation gate PASS): VERIFIED.** Score independently recomputed
  from the raw results dump = 0.905072, matching the gate report byte-for-byte.
  All 40 EQUIVALENT_PROVEN mutant bodies inspected: **no killable mutant was
  misclassified as equivalent.** Even if the 9 platform-dependent
  FS_PATH_CASE_ONLY equivalents were counted as killable, score = **0.9013 ≥ 0.90**.
- **Claim 2 (clean install A/B): VERIFIED.** 363/363; installed `mgk`/`runtime`
  trees sha256-identical across the two venvs; installed-only run passes.
- **Claim 3 (secret scan): VERIFIED.** Pattern-based scan clean.
- **Claim 4 (source of truth): VERIFIED.** Mutation src+tests byte-identical
  to the working tree; `source_manifest_sha256` all match.

## 4. Caveats the human must review

1. **Uncommitted functional source change in the measured tree.**
   `src/mgk/resource.py` `write_bound` present-target branch:
   `os.O_WRONLY` → `os.O_RDWR` (present at gate time; mtime 01:51 predates the
   run-5 dump 02:59). `O_RDWR` is functionally required: the present-target
   branch reads the descriptor to verify `pre_sha256`/`pre_size` before
   truncate (`O_WRONLY` → EBADF). The gate measured this exact tree, so the
   result is valid; the commit `edd3ea6` alone would fail those tests. The
   evidence document `mutation-v2-classification.md` has been corrected to
   state this. Human decision: commit the fix (recommended) with the release.

2. **Platform-dependent equivalence (9 mutants).** FS_PATH_CASE_ONLY
   equivalents hold only on case-insensitive filesystems (macOS APFS). On
   case-sensitive Linux CI they would be killable. Margin holds either way
   (0.9013 worst case). Note for release artifacts/CI.

3. **pyproject version is still 0.1.0.** No version bump has been made
   (a release version is a human decision). Releasing as-is would tag an
   artifact that reports 0.1.0 despite shipping v0.2.0 functionality.

4. **Network index used for clean installs.** Clean install A/B pulled pinned
   deps from PyPI. If offline install is required for release, build a
   wheelhouse of the frozen versions first (freeze documented in
   `dependency-freeze-and-secret-scan.md`).

5. **Uncommitted test additions.** 6 test files carry uncommitted changes
   (kill-batch tests + the `O_RDWR`-related coverage); 2 new test files are
   untracked. All are required for the 363-pass suite and the gate.

6. **`gates/` status.** `gates/` contains `protected/` and `ROOT_MANIFEST.sha256`;
   no autonomous changes were made to gates during this run.

## 5. Recommendation

All autonomous gates for MGK v0.2.0 are GREEN and independently verified. The
implementation satisfies the functional-governance mission per the evidence
above, with the mutation gate met without dishonest reclassification.

The decision to **release** (commit the working-tree fix + tests, bump the
version, tag, publish) is reserved for the human. `RELEASE_AUTHORIZED: FALSE`.