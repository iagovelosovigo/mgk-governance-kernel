# MGK v0.1.0 — independent red-team corpus

This directory is intentionally separate from the builder candidate. It contains
an authority-oriented threat model, a traceable attack matrix, a declarative
41-vector corpus and a black-box runner. It does not modify or trust the
candidate implementation.

## Deterministic corpus validation

```bash
python validate_artifacts.py
python -m unittest -v test_redteam_corpus.py
```

The expected validation summary is:

```json
{"attack_categories":19,"attacks":19,"critical_attacks":18,"invariants":15,"orphaned_vectors":0,"schema_version":"1.0","status":"PASS","vectors":41}
```

## Candidate attack execution

An adapter executable receives one test-vector JSON document on stdin and emits
one result JSON document on stdout. The exact protocol and step vocabulary are
frozen in `adapter-contract.json`.

```bash
python run_attacks.py \
  --out redteam-results.json \
  --adapter-command -- python path/to/mgk_redteam_adapter.py
```

`run_attacks.py` treats adapter crashes, timeouts, invalid JSON and missing
observables as failures. Expected observables are compared as a required subset,
so an adapter may report more evidence but cannot omit the effect counter,
decision, stable reason, audit presence or evidence-preservation result.

## Files

- `threat-model.json`: assets, roles, trust boundaries, adversaries and 15 invariants.
- `attack-matrix.json`: 19 traceable attacks covering every mandatory category.
- `test-vectors.json`: positive control plus 40 hostile vectors.
- `adapter-contract.json`: candidate-neutral execution protocol.
- `run_attacks.py`: strict black-box runner and machine-readable report producer.
- `findings.json`: confirmed bootstrap findings and provisional review verdict.
- `proof-unbound-gate-subject.json`: executable proof for MGK-RT-BOOT-001.
