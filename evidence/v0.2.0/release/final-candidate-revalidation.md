# MGK v0.2.0 — Final Candidate Revalidation (Phase 5)

Candidate: FINAL_COMMIT_SHA `1327e5e85a44b3a917a0472b7de2e6a202326c8b`
FINAL_TREE_SHA `716527089f40ad881520d3944c01b238d8d3e862`
Version: 0.2.0 | Date: 2026-08-17

All checks run against the final candidate tree (working tree verified identical to
`716527089f40ad881520d3944c01b238d8d3e862` for all source/test/metadata; only later
evidence additions differ).

| Check | Result |
|---|---|
| Root of Trust (`MGK_ROOT_MANIFEST_SHA256=4c309aad…` + `orchestrator/tcb/trust.py`) | **PASS** — "Protected tree verified." (manifest self-hash 4c309aad… matches anchor) |
| Full regression suite (`pytest tests`) | **363 passed** |
| Runtime tests (in suite) | included, all pass |
| Security/H14 tests (in suite incl. `test_h14.py`, red-team) | all pass |
| Deterministic acceptance gates (`tools/scenarios_v2.py` A–J) | **PASS** — all 10 scenarios, doctor PASS |
| Red team (`tools/redteam_v2.py`) | **PASS** — all 15 findings (R1–R14 + same-origin), `all_pass: true`, post-attack doctor PASS, post-attack test PASS (h14_proposal_is_not_authority) |
| CLI smoke (`mgk h14-smoke`) | **PASS** — result PASS, h14_forbidden_executions 0, rc 0 |
| Secret scan (git-tracked, final candidate) | **PASS** — no private keys, tokens, credential assignments, key files |
| Dependency freeze | **PASS** — requirements.lock (cryptography 46.0.0, pytest 8.4.1, hypothesis 6.138.13, pytest-timeout 2.4.0) matches pyproject runtime dep |
| Clean install A (fresh venv, non-editable install of final repo) | **PASS** — 363 passed; installed dist version **0.2.0**; `mgk.__version__` **0.2.0** |
| Clean install B (fresh venv) | **PASS** — 363 passed |
| Installed-only (top-level `runtime/` source moved aside) | **PASS** — 363 passed from site-packages |
| Reproducibility | **PASS** — installed `mgk` (17 files) and `runtime` (10 files) trees sha256-identical A vs B; pip freeze identical |

## Notes

- Browser (playwright) acceptance was recorded during the completed pipeline
  (`evidence/v0.2.0/browser/browser_acceptance.json`, commit `9bc5e84`). Playwright is not
  present in the closure venvs, so browser smoke is not re-executed; the version bump did
  not change runtime web behavior (verified by scenarios A–J and red-team API attacks on the
  final tree).
- Minor freeze drift vs the earlier record: transitive `Pygments` 2.20.0 -> 2.21.0 (not a
  package dependency and not pinned). All pinned runtime/test deps identical.
