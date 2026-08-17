# Independent Examiner Findings — MGK v0.2.0 Functional Governance Runtime

- Examiner: independent/adversarial (no builder context; evidence verified from scratch)
- Date: 2026-08-17
- Verifier venv python: `/var/folders/bf/7f75557n44s0d89v_dx0l7cr0000gn/T/opencode/mgk-verify/venv/bin/python`
- Scope: 4 evidence claims. No source/tests modified; only reads and verification commands were run.

---

## Claim 1 — Mutation gate PASS

### Verdict: VERIFIED

### 1a. Score recomputation (raw results → classification → gate)

Commands run:

```
PYTHONPATH=.../tools venv/bin/python tools/mutation_gate_v2.py \
  --results evidence/v0.2.0/mutation/mutation-v2-results.txt \
  --classification evidence/v0.2.0/mutation/mutation-v2-classification.json \
  --out /tmp/.../gate-recheck.json
```

Independent recomputation script (`recompute.py`) parsed the results dump with the
same regex the gate uses:

| Quantity | Recomputed | Reported |
|---|---|---|
| Total result lines | 2189 | 2189 |
| `killed` lines | 1945 | — |
| `survived` lines | 244 | — |
| `timeout` / `no tests` / `suspicious` | 0 / 0 / 0 | — |
| Classification KILLED | 1945 | 1945 |
| Classification SURVIVED_KILLABLE | 204 | 204 |
| Classification EQUIVALENT_PROVEN | 40 | 40 |
| EVALUABLE = KILLED + SURVIVED_KILLABLE | 2149 | 2149 |
| MUTATION_SCORE_V2 = 1945 / 2149 | **0.905072** | **0.905072** |
| Verdict at threshold 0.90 | **PASS** | **PASS** |

Cross-checks (all clean):
- 0 rows where `run_status` disagrees with classification (all KILLED have run_status `killed`).
- 0 survivors reclassified to KILLED (no `--reclassified-killed` entries used).
- 0 result ids missing from classification; 0 classified ids missing from results.
- Gate-tool rerun reproduced the on-disk `mutation-v2-gate-report.json` byte-for-byte (EVALUABLE 2149, score 0.905072, PASS).

### 1b. Gate tool enforces threshold 0.9; EQUIVALENT_PROVEN excluded from denominator

Read: `tools/mutation_gate_v2.py`, `tools/build_classification.py`, `tools/mutation_classifier_v2.py`, and `contracts/MGK-MUTATION-GATE-V2.yaml`.

- `mutation_gate_v2.py:68-74` computes `EVALUABLE = KILLED + SURVIVED_KILLABLE` and
  `score = KILLED / EVALUABLE`; verdict is PASS only when `score >= 0.90`, `INDETERMINATE == 0`, and `EVALUABLE > 0`. This matches the contract metric (`EVALUABLE: KILLED + SURVIVED_KILLABLE`, `threshold: 0.90`, pass conditions).
- `EQUIVALENT_PROVEN`, `INVALID_MUTANT`, `UNREACHABLE_PROVEN` are counted but excluded from the denominator — exactly what the contract's `EVALUABLE` definition requires. `INDETERMINATE` forces `FAIL_CLOSED`.
- The classifier (`mutation_classifier_v2.py`) returns `EQUIVALENT_PROVEN` only from: (i) a hard-coded allowlist (`SQL_EQUIVALENT_IDS`, `ENCODE_EQUIVALENT_IDS`), or (ii) `probe_equivalent()` which requires a detected transformation family with a documented runtime-probe justification. `build_classification.py` attaches the orig-vs-variant diff as per-mutant `evidence`. This matches the contract's `exclusion_requires_evidence` requirement.

### 1c. HONESTY CHECK — the 40 EQUIVALENT_PROVEN mutants

I extracted and read **all 40** mutant bodies from the mutmut mutant copies
(`mutmut-v2/mutants/src/mgk/*.py` — note: in this run the files are `.py`, not `.x`,
but each contains the `def xǁClassǁfuncǁmutmut_N(...)` copied functions as described)
and compared each against its `__mutmut_orig` original and against the repo source.

Breakdown by family (all 40 inspected):

| Family | Count | Mutants inspected | Judgment |
|---|---|---|---|
| FS_PATH_CASE_ONLY | 9 | cli.x_h14_smoke mutmut_4, 8, 14, 16, 34, 93, 96, 108, 111 | Equivalent on eval FS |
| NOOP | 4 | crypto b64u_encode mutmut_6, 7; b64u_decode mutmut_29, 30 | Byte-identical body = equivalent |
| CODEC_CASE_ONLY | 1 | crypto b64u_encode mutmut_9 | Equivalent |
| RESOLVE_STRICT_ONLY | 2 | resource ResourceGuard.__init__ mutmut_9, 10 | Equivalent |
| GETATTR_DEFAULT_ONLY | 24 | resource open_file 7,10,13; open_parent 8,11,14; append_bound 41,44,47; bind_write 21,24,27; create_bound 54,57,60; remove_created 28,31,34; write_bound 84,87,90,107,110,113 | Equivalent |

Per-mutant judgments:

- **NOOP (4):** the mutated body is byte-for-byte identical to `__mutmut_orig` after
  the rename (mutmut duplicate). Behavior identical by construction. Not killable.
- **CODEC_CASE_ONLY (b64u_encode mutmut_9):** `.decode("ascii")` → `.decode("ASCII")`.
  Python codec names are case-insensitive; verified `"ascii"` and `"ASCII"` resolve to
  the same codec. Equivalent. Not killable.
- **GETATTR_DEFAULT_ONLY (24):** `getattr(os, "O_NOFOLLOW", 0)` default changed to
  `None`/`1`/omitted, and `getattr(os, "O_DIRECTORY", 0)` similarly. Verified on the
  eval platform: `os.O_NOFOLLOW = 256`, `os.O_DIRECTORY = 1048576` both exist on darwin,
  so the changed default is never consulted. All variants produce identical flags.
  Equivalent. Not killable.
- **RESOLVE_STRICT_ONLY (2):** `path.resolve(strict=True)` → `strict=None`/`strict=False`.
  The guard raises earlier when `path.is_symlink() or not path.is_dir()`, so by the time
  `resolve()` runs the root exists as a real directory. Probe-verified on this platform:
  `resolve(strict=True)` == `resolve(strict=False)` == `resolve(strict=None)` for an
  existing dir. Equivalent. Not killable.
- **FS_PATH_CASE_ONLY (9):** path-component case changes only
  (`workdir/"failures.jsonl"` → `workdir/"FAILURES.JSONL"`, `resources`→`RESOURCES`,
  `workspace`→`WORKSPACE`, `allowed.txt`→`ALLOWED.TXT`, `security.sqlite`→`SECURITY.SQLITE`,
  `audit.jsonl`→`AUDIT.JSONL`, `audit.checkpoint.json`→`AUDIT.CHECKPOINT.JSON`,
  `failures.checkpoint.json`→`FAILURES.CHECKPOINT.JSON`).
  I independently verified the eval filesystem is **case-insensitive**
  (APFS on this macOS host; a probe creating `MixedCase` was found by `mixedcase`).
  On a case-insensitive FS these paths name the same files, and the smoke function is
  deterministic and its test asserts only the returned dict plus `tmp_path` files which
  resolve identically. **Equivalent on the evaluation platform** — this is the
  platform-dependence caveat noted below, not a killable misclassification.

**Result: zero of the 40 EQUIVALENT_PROVEN mutants appears to be a killable mutant
misclassified to inflate the score.** All 40 are genuinely behaviorally identical on
the evaluation platform.

### 1d. Sanity — full test suite

Command:

```
cd /Users/iagoveloso/mgk-governance-kernel && \
PYTHONPATH=.../src:... venv/bin/python -m pytest tests -q -p no:cacheprovider
```

Result: **363 passed** (4.82s). Claimed 363 — confirmed.

---

## Claim 2 — Clean install A/B reproducible

### Verdict: VERIFIED

Commands:

```
cd .../ab-check/repo && venv-a/bin/python -m pytest tests -q -p no:cacheprovider
cd .../ab-check/repo && venv-b/bin/python -m pytest tests -q -p no:cacheprovider
```

Results:

| Check | Result |
|---|---|
| Suite in venv A | **363 passed** (4.92s) |
| Suite in venv B | **363 passed** (4.70s) |
| `import mgk` resolves to site-packages in A | yes (`.../venv-a/lib/python3.12/site-packages/mgk/__init__.py`) |
| site-packages `mgk` tree sha256 A vs B (17 .py files, no `__pycache__`) | **identical** (0 diffs) |
| site-packages `runtime` tree sha256 A vs B (10 .py files) | **identical** (0 diffs) |
| `pip freeze` A vs B | **identical** |
| Installed-only run (top-level `runtime/` moved aside) in venv A | **363 passed** — `import runtime` resolves to site-packages |

The `runtime/` dir was moved aside in the disposable ab-check copy only, then restored.

---

## Claim 3 — Secret scan clean

### Verdict: VERIFIED (with note)

My own grep scans across the working tree AND git-tracked content, excluding
`evidence/`, `redteam/`, `independent_exam/`, `.git/`:

| Pattern | Hits |
|---|---|
| `BEGIN (RSA|EC|OPENSSH|DSA|ENCRYPTED)? PRIVATE KEY` | 0 |
| `AKIA[0-9A-Z]{16}` (AWS) | 0 |
| `ghp_[A-Za-z0-9]{36}` (GitHub) | 0 |
| `sk-[A-Za-z0-9_-]{24,}` (OpenAI-style) | 0 |
| `xox[baprs]-[A-Za-z0-9-]{10,}` (Slack) | 0 |
| `AIza[0-9A-Za-z_-]{35}` (Google) | 0 |
| `*.pem` / `*.key` / `*.p12` / `*.env` files | 0 |
| `password|passwd|secret|api_key|apikey|access_token|auth_token = "<6 chars>"` | 0 |
| Long base64 blobs (≥64 chars) in `src/`/`runtime/`/`tools/` | 0 |

Key material is generated at runtime only (`runtime/workspace.py:_load_or_generate_key`,
mode `0o600`, `O_EXCL`), never committed. The single `b"secret"` string in
`tests/test_resources.py` is a test payload, not a credential.

Note: I did not independently re-run a full entropy-scan tool (e.g. trufflehog); the
verification above is pattern-based grep, matching the evidence's stated methodology.

---

## Claim 4 — Source of truth (mutation run == repo working tree)

### Verdict: VERIFIED

sha256 comparison, repo working tree vs `mgk-verify/mutmut-v2`:

- Full `src/mgk/*.py` (17 files): **all MATCH**.
- Full `tests/*.py` (26 files): **all MATCH**.
- Specifically required by the brief: `src/mgk/resource.py` MATCH,
  `tests/test_mutation_v2_verifier.py` MATCH, plus `cli.py`, `crypto.py`,
  `executor.py`, `verifier.py`, `authority.py`, `test_mutation_v2_resource.py`,
  `test_mutation_v2_cli.py`, `test_mutation_v2_executor.py`, `test_mutation_v2_crypto.py`,
  `test_mutation_v2_canonical.py`, `test_h14.py` — **all MATCH**.
- `mutation-v2-findings.json` `source_manifest_sha256` (44 entries): **all match the
  current working tree** (0 mismatches).
- ab-check repo vs main repo spot-check (`resource.py`, `test_mutation_v2_verifier.py`,
  `test_mutation_v2_resource.py`): all MATCH.

---

## Discrepancies and risks

1. **Uncommitted functional source change present at gate time.** `git status` shows
   `src/mgk/resource.py` modified vs HEAD: in `write_bound`, the present-target branch
   flag changed from `os.O_WRONLY` to `os.O_RDWR`. This is a behavioral change to the
   resource write path. mtime (01:51) predates the mutation result dump (02:59), and the
   mutated copy is byte-identical to the working tree, so the mutation run **did** cover
   this source state — the gate result is valid for the current tree. However,
   `mutation-v2-classification.md` states *"No source changes were made to reach this
   gate; only tests were strengthened."* That statement is **not fully accurate**: a
   functional, uncommitted change to `resource.py` is present in the tree that the gate
   measured. This does not change the recomputed score (the tree was measured as-is),
   but the provenance claim overstates "no source changes."

2. **Platform-dependent equivalence (FS_PATH_CASE_ONLY).** 9 of the 40 equivalent
   mutants are equivalent only because the eval filesystem is case-insensitive (macOS
   APFS). On a case-sensitive filesystem (e.g. Linux CI) these 9 mutations would be
   killable. The classifier documents this dependency explicitly ("evaluation filesystem
   is case-insensitive"); it is honest but environment-sensitive. If the score were
   recomputed counting those 9 as killable: 1945 / 2158 = **0.9013** — still ≥ 0.90.
   Even if all 9 FS_PATH_CASE_ONLY were disputed, the gate still passes.

3. **Sensitivity margin.** Score 0.905072 is 0.005072 above threshold. Re-classifying any
   EQUIVALENT_PROVEN mutants as killable would move the score only if enough were
   disputed. Counting all 9 FS_PATH_CASE_ONLY as killable yields 0.9013 (pass); counting
   all 40 as killable yields 1945 / 2189 = 0.8885 (fail). I found no evidence that any
   should be counted as killable — see 1c.

4. **V1 history is preserved in contract** (v1 score 76.1 / combined 90.23 invalidated,
   timeout artifact documented) — consistent with the contract file; no discrepancy.

5. Minor: the evidence brief describes mutant copies as `*.x` files; in this run the
   mutant copies are `*.py` files in `mutmut-v2/mutants/src/mgk/`. Cosmetic; the
   `def xǁClassǁfuncǁmutmut_N` structure is present as described.

---

## Final verdict

**Does the evidence support "mutation gate PASS at >= 0.90 without dishonest reclassification"? — YES.**

- Score independently recomputed from the raw results dump: **1945 / 2149 = 0.905072**,
  matching the gate report exactly; verdict PASS at threshold 0.90.
- The gate tool enforces the contract formula (KILLED / (KILLED + SURVIVED_KILLABLE),
  INDETERMINATE → FAIL_CLOSED) and excludes only evidence-backed EQUIVALENT_PROVEN from
  the denominator, as the contract requires.
- Honesty sample: all 40 EQUIVALENT_PROVEN mutants inspected from their actual mutant
  bodies; **no killable mutant was misclassified as equivalent**. All exclusions are
  behaviorally identical on the evaluation platform (byte-identical NOOP bodies, codec
  case-insensitivity, existing `os.O_NOFOLLOW`/`O_DIRECTORY` defaults never used,
  `resolve` strict-flag irrelevance on an existing dir, and case-only path changes on a
  case-insensitive filesystem).
- Full suite: 363 passed. Clean-install A/B: 363/363, installed trees byte-identical.
  Secret scan: clean. Source-of-truth: mutation src+tests byte-identical to the working
  tree.

One caveat raised but not disqualifying: the classification.md claim of "no source
changes" is inaccurate relative to HEAD (an uncommitted `O_WRONLY`→`O_RDWR` change in
`resource.py` was present in the measured tree), and the FS_PATH_CASE_ONLY equivalences
are dependent on the case-insensitive eval filesystem. Neither changes the recomputed
score nor the honest-equivalence conclusion.