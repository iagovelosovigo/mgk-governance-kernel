# MUDA Governance Kernel v0.3.0

MGK is a capability-secured local governance kernel whose executable invariant is:

> Intelligence is not authority (`I != A`).

Planners may propose actions. Only the deterministic SAXP policy and an Ed25519 authority
may issue a narrowly bound, short-lived capability. The executor rejects every action lacking
a valid capability, consumes nonces atomically, rechecks the authorization epoch immediately
before commit, binds resources by descriptor and digest, and preserves signed-checkpoint
audit and failure ledgers.

The canonical boundary between the MUDA conceptual/formal kernel, the MUDA operational
kernel, the wider Malla MUDA, the MGK governance kernel, external intelligence systems,
actuators/executors, and human authority is defined in
`ARCHITECTURE-MUDA-MGK-BOUNDARY.md`. The v0.3.0 scope contract is
`contracts/MGK-V0.3.0-SCOPE.json`. MGK is an engineering implementation derived from MUDA
concepts; it does not claim universal scientific proof of MUDA.

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

## v0.3.0 authority-boundary hardening

A human `DENY` (and a policy `DENY`) is now a durable terminal state. Approving a proposal
that was already denied, already executed, or is otherwise not in the `REQUIRE_HUMAN`
review state is refused fail-closed (`HUMAN_GATE_TRANSITION_DENIED`) and can never issue a
capability or execute a side effect.
