# Phase 12 — Independent Verification Exam (v0.2.0 Security-Mutation-Adequacy Campaign)

Date: 2026-08-17
Examiner stance: independent/adversarial. No recorded summary is trusted;
all headline claims recomputed from raw artifacts (read-only; no source or
tests modified).

## Method

`tools/security_mutation/independent_verification.py` recomputes every
claim from its raw source of truth:

- **C1** — Mutation population and score recomputed directly from the raw
  mutmut results dump (`results_all_phase8b.txt`, 3314 lines) using a
  fresh parser; cross-checked against `population-fresh.json` and
  `security-adequacy-gate.json`.
- **C2** — All 7 `phase8-fresh-survivor-addendum.json` entries must be
  `EQUIVALENT_PROVEN`, unique, and actually present in the raw results.
- **C3** — `redteam-adversarial.json` must be all-PASS with 33 unique probes,
  correct schema (`mgk.redteam.v1` / `redteam-adversarial`), and 0 fails.
- **C4** — `clean-install-ab.json` must show identical suite outcomes
  (407/407/407) and identical installed tree hashes.
- **C5** — `phase11-secrets-root-of-trust.json` must record the 0700/0600
  hardening and zero mutation-population impact (no `src/mgk` change).

Live re-verification on the current tree (final code):
- Full suite: **408 passed** (includes Phase-11 perms regression test).

## Results

| Claim | Independent recomputation | Verdict |
|---|---|---|
| C1 mutation score | 3314 total, 3034 killed, 280 survived, 0 timeout, score **0.915510** | VERIFIED |
| C1b gate record | gate score 0.91551, population total 3314, gate PASS | VERIFIED |
| C2 addendum | 7 EQUIVALENT_PROVEN, all present & unique in raw results | VERIFIED |
| C3 red-team | 33 findings, 33 PASS, 0 FAIL, schema correct | VERIFIED |
| C4 clean install | 407/407/407, identical installed trees (17 mgk, 10 runtime) | VERIFIED |
| C5 phase 11 | 0700 dirs / 0600 sqlite, no src/mgk change | VERIFIED |
| Live suite (final code) | 408 passed | VERIFIED |

`all_claims_verified: true`, failures: none.

## Conclusion

Every headline claim of the security-mutation-adequacy campaign (Phase 8 gate
score 0.915510 ≥ 0.90; Phase 9 red-team 33/33; Phase 10 clean-install
reproducibility; Phase 11 permission hardening) survives independent
recomputation from raw evidence with zero discrepancies.