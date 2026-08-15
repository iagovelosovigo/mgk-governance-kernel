# MUDA Governance Kernel v0.1.0

MGK is a capability-secured local governance kernel whose executable invariant is:

> Intelligence is not authority (`I != A`).

Planners may propose actions. Only the deterministic SAXP policy and an Ed25519 authority
may issue a narrowly bound, short-lived capability. The executor rejects every action lacking
a valid capability, consumes nonces atomically, rechecks the authorization epoch immediately
before commit, binds resources by descriptor and digest, and preserves signed-checkpoint
audit and failure ledgers.

## Quick verification

```bash
python -m pip install -r requirements.lock
python -m pip install -e .
pytest -q
mgk h14-smoke
```

The `independent_exam/` directory is a frozen examination produced independently from the
main implementation. `contracts/MGK-FUNCTIONAL-ACCEPTANCE.yaml` defines the release verdict
as machine-readable gates rather than an agent opinion.

## Runtime limits

The v0.1.0 action registry intentionally contains only `resource.read` and
`resource.create`. The epoch rollback floor must be supplied from an operator-controlled
external anchor when a process restarts. Filesystem-wide rollback of both state and that
external anchor is outside the local threat boundary and is never treated as authorized.
