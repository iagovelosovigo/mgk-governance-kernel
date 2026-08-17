# MGK v0.2.0 — Evidence Consistency Audit / Reconciliation (Phase 7)

No evidence was silently rewritten. Historical files are preserved; corrections and
dispositions are recorded below. Audit target: every statement about version, commit/tree,
source changes, test/mutation counts, worktree state, and install hashes.

| Evidence | Class | Disposition |
|---|---|---|
| mutation-v2-classification.md | CORRECTION | Already corrected during closure: the measured tree contained the uncommitted O_WRONLY->O_RDWR fix vs HEAD; statement changed from "no source changes" to explicit correction. |
| mutation-v2-findings.json | HISTORICAL OBSERVATION | `source_manifest_sha256[src/mgk/__init__.py] = e3c9742…` was accurate for the mutation-tested tree. FINAL candidate `__init__.py` = `4fc01d49…` (version bump only). Not rewritten; final hash recorded here. |
| mutation-v2-gate-report.json | FINAL CANDIDATE FACT | 0.905072 / PASS; valid for FINAL tree via source equivalence (Phase 6). |
| mutation-v2-results.txt | HISTORICAL OBSERVATION | raw run-5 dump, unchanged. |
| install/clean-install-ab.md | HISTORICAL OBSERVATION | pre-bump A/B. FINAL A/B in final-candidate-revalidation.md. |
| install/dependency-freeze-and-secret-scan.md | FINAL CANDIDATE FACT | pins match final pyproject; secret scan re-run on FINAL tree (PASS). Transitive Pygments 2.20.0->2.21.0 noted (not pinned). |
| independent-exam/FINDINGS.md | HISTORICAL OBSERVATION | verified pre-bump tree; flagged O_RDWR. Phase 8 final exam binds to FINAL commit/tree. |
| release/HUMAN-RELEASE-GATE.md | SUPERSEDED | pre-closure report (HEAD 5f069ad, version 0.1.0). Superseded by HUMAN-RELEASE-GATE-FINAL. |
| release/pre-closure-state.{json,md} | HISTORICAL OBSERVATION | accurate at capture. |
| release/candidate-identity.{json,md} | FINAL CANDIDATE FACT | 1327e5e / 71652708…, 0.2.0. |
| release/final-candidate-revalidation.md | FINAL CANDIDATE FACT | Phase 5 results. |
| release/mutation-source-equivalence.md | FINAL CANDIDATE FACT | Phase 6 binding. |
| browser/browser_acceptance.json | HISTORICAL OBSERVATION | playwright evidence from completed pipeline; API re-verified on FINAL tree (scenarios + red-team). |

## Version-identifier audit (current vs historical)

- **Updated to 0.2.0 (CURRENT CANDIDATE metadata):** pyproject.toml `version`,
  `src/mgk/__init__.py` `__version__` + docstring, README-MGK.md title, NOTICE.md
  "MGK v0.2.0 is an engineering implementation…".
- **Preserved (historical / contract / schema):** README.md "MGK v0.1.0 - FUNCTIONAL = TRUE"
  (historical contract outcome); contracts `MGK-v0.1.0-mutation-gate-2` and
  `MGK-v0.1.0-independent-exam-1` (contract/schema identifiers); tools contract_id fields;
  all frozen v0.1.0 evidence; tag `v0.1.0` at `130606b`.

## Consistency findings

- Test count 363 consistent across all evidence (pre-bump and FINAL revalidation).
- Mutation counts 1945/2149/204/40/0/0.905072 consistent; transferred via source
  equivalence; no denominator weakening, no survivor hiding, no silent reclassification.
- Clean-install hashes: pre-bump evidence retained; FINAL A/B hashes recorded in
  final-candidate-revalidation.md (mgk 17 files, runtime 10 files, A==B).
- No stale claims of "no source changes" remain (classification.md corrected).
- No v0.1.0 identifier is presented as v0.2.0 candidate identity.