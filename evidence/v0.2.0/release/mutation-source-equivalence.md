# MGK v0.2.0 — Mutation Evidence Binding (Phase 6)

## Decision: MUTATION_SOURCE_EQUIVALENCE: PASS (evidence carried forward)

## Mechanical comparison

All `src/mgk/*.py` of the FINAL candidate (`716527089f40ad881520d3944c01b238d8d3e862`)
hashed (sha256) and compared against the mutation-tested source
(`mgk-verify/mutmut-v2/src/mgk/`):

| File | Final vs mutation-tested |
|---|---|
| authority.py | MATCH |
| cli.py | MATCH |
| crypto.py | MATCH |
| executor.py | MATCH |
| resource.py | MATCH |
| verifier.py | MATCH |
| arrow.py, canonical.py, cha.py, clock.py, errors.py, feedback.py, ledger.py, models.py, saxp.py, state.py | MATCH (all) |
| **__init__.py** | **DIFFERS** — only `"""…v0.1.0…"""` -> `"""…v0.2.0…"""` and `__version__ = "0.1.0"` -> `"0.2.0"` |

## Why the __init__.py difference does not invalidate the mutation result

1. The mutation population (`mutation-v2-classification.json`) contains mutants in exactly
   six modules: **authority (266), cli (370), crypto (107), executor (281), resource (773),
   verifier (392)** — total 2189. All six are byte-identical to the mutation-tested source.
2. `src/mgk/__init__.py` contributes **0 mutants** to the population (verified: no
   `module == "__init__"` entries). It was copied into the mutmut working copy but produced
   no mutations.
3. The only change in `__init__.py` is the pure version constant, which is non-behavioral
   (no code path in the mutated modules reads `mgk.__version__`).
4. Tests used by the mutation run are byte-identical to the final candidate tests (independent
   exam Claim 4; version bump touched no test files).

Per the closure rule, a pure version change in a source file that is OUTSIDE the
mutation-tested mutant population does not invalidate the previous mutation result.

## Carried-forward mutation evidence (valid for FINAL candidate tree)

| Quantity | Value |
|---|---|
| KILLED | 1945 |
| EVALUABLE | 2149 |
| SURVIVED_KILLABLE | 204 |
| EQUIVALENT_PROVEN | 40 |
| INDETERMINATE | 0 |
| MUTATION_SCORE | 0.905072 |
| THRESHOLD | 0.90 |
| RESULT | PASS |
| MUTATION_EVIDENCE_MODE | SOURCE_EQUIVALENCE |
