# MGK v0.3.0 — Gap Analysis

Status: complete for v0.3.0 planning. Classified per contract
`contracts/MGK-V0.3.0-SCOPE.json`. Each gap carries one of:
NO_ACTION, DOCUMENTATION_GAP, TEST_GAP, IMPLEMENTATION_GAP, SECURITY_GAP,
ARCHITECTURE_MISMATCH, OUT_OF_SCOPE.

Baseline: v0.2.0 (commit 90b84bc8cd53489351a33412411c8030082f1d43).

---

## GAP-01 — Architecture boundary between MUDA and MGK not documented

- Observation: `evidence/v0.2.0/architecture/architecture.md` documents the
  runtime architecture but does not distinguish the MUDA conceptual/formal
  kernel (h x K = C0 equilibrium), the MUDA operational kernel (Rrep/Rlim/
  Rcog/CCI), the wider Malla MUDA, and the MGK governance kernel. There is no
  explicit status classification per concept, and no explicit non-claim about
  universal scientific proof.
- Classification: DOCUMENTATION_GAP, ARCHITECTURE_MISMATCH
- Resolution (v0.3.0): `ARCHITECTURE-MUDA-MGK-BOUNDARY.md` is the canonical
  boundary document with explicit status labels and non-claims.

## GAP-02 — No machine-readable v0.3.0 scope contract

- Observation: no scope contract exists that pins what v0.3.0 changes, does
  not change, its authority invariants, threat model, backward compatibility,
  and acceptance/release gates.
- Classification: DOCUMENTATION_GAP
- Resolution (v0.3.0): `contracts/MGK-V0.3.0-SCOPE.json`.

## GAP-03 — Version identifiers stale for a v0.3.0 candidate

- Observation: `pyproject.toml`, `src/mgk/__init__.py`,
  `runtime/__init__.py`, and `README-MGK.md` report 0.2.0.
- Classification: DOCUMENTATION_GAP
- Resolution (v0.3.0): version bump to 0.3.0 (package metadata + kernel
  runtime version strings). No test asserts the package version, and the
  frozen independent exam records its own historical label, so the bump is
  backward-compatible.

## GAP-04 — Human DENY is not durable (unauthorized human-gate transition)

- Observation: `runtime/decision.py` `human_approve`/`human_deny` do not
  consult the current decision state. A proposal whose SAXP result was
  `REQUIRE_HUMAN` and that a human DENIED can be APPROVED later; a policy
  DENY (`NON_TEN_XEITO`) can also be overridden by a later approve. The
  runtime ledger's `decisions` row is last-write-wins, so an APPROVE
  overwrites a DENY. This is the "unauthorized human-gate transition" attack
  class: a human-review state can eventually execute despite a recorded
  denial.
- Classification: SECURITY_GAP (authority-boundary hardening)
- Resolution (v0.3.0): durable human-gate state machine in
  `runtime/decision.py`. Only `REQUIRE_HUMAN` proposals are actionable;
  `DENY` (human or policy) and executed `ALLOW` are terminal. Any other
  transition is refused fail-closed with evidence event
  `HUMAN_GATE_TRANSITION_DENIED`. Protected by permanent discriminating
  regression tests and new adversarial probes.
- Note: This does not weaken the v0.2.0 behavior of any required gate; the
  red-team probes A9 (double-approve) and A10 (deny no side effect) continue
  to pass.

## GAP-05 — Adversarial corpus lacks human-gate transition probes

- Observation: `tools/redteam_adversarial_v9.py` covers A9 (double-approve)
  and A10 (deny-no-side-effect) but has no probe for approve-after-deny,
  deny-after-execute, or approve-after-auto-allow.
- Classification: TEST_GAP
- Resolution (v0.3.0): add probes A23 (approve-after-deny must not execute),
  A24 (deny-after-execute refused), A25 (approve on auto-ALLOWED proposal
  refused).

## GAP-06 — No discriminating regression tests for the durable deny state

- Classification: TEST_GAP
- Resolution (v0.3.0): add permanent tests to `tests/test_runtime.py`
  asserting approve-after-deny / approve-after-execute / deny-after-execute /
  double-deny fail closed without side effects.

## GAP-07 — Mutation-adequacy contract lists runtime modules but the executed
canonical population is src/mgk only

- Observation: `contracts/MGK-SECURITY-MUTATION-ADEQUACY-V1.yaml` defines the
  population as FULL `src/mgk` plus security-critical `runtime/*` modules,
  but the executed canonical run (`pyproject.toml [tool.mutmut]
  paths_to_mutate=["src/mgk"]`) mutates `src/mgk` only; `also_copy` copies
  runtime without mutating it. The v0.2.0 gate score (0.91551) is therefore
  over `src/mgk` (3314 mutants).
- Classification: DOCUMENTATION_GAP (contract wording vs. executed procedure)
- Resolution (v0.3.0): the canonical mutation gate remains the full
  `src/mgk` population (no do_not_mutate, matching the executed v0.2.0
  procedure). The gap between contract wording and executed population is
  documented here and in the v0.3.0 claim audit. The runtime human-gate
  change is covered by permanent discriminating tests; runtime modules remain
  outside the mutmut population (as in v0.2.0) and are listed as a known
  limitation.

## GAP-08 — Flight recorder checkpoint is unsigned (evidence-only)

- Observation: `runtime/flight.py` checkpoints are plain `{count, head_hash}`
  while the audit/failure ledgers use signed checkpoints. The flight recorder
  is explicitly evidence-only (not a trust source) and is verified by
  `doctor`/tests.
- Classification: NO_ACTION (documented evidence-only role; signed-checkpoint
  strengthening deferred; not required by any contract gate)
- Note: recorded as a known limitation in release notes.

## GAP-09 — RuntimeConfig.epoch is dead configuration

- Observation: `runtime/config.py` `RuntimeConfig.epoch` is never consumed;
  `workspace.py` always initializes epoch 1. The epoch rollback floor must be
  supplied externally on restart (documented in README-MGK.md).
- Classification: NO_ACTION (avoid speculative complexity; existing behavior
  documented; out of the local threat boundary)

## GAP-10 — Human-gate web API is unauthenticated (loopback-only)

- Observation: `runtime/web.py` `_api_human` has no operator authentication;
  operator defaults to "operator". Same-origin CSRF check is browser-only.
- Classification: NO_ACTION (loopback-only surface within the documented
  threat model; operators are local; adding auth would be a new feature,
  out of the minimal change set). Recorded as a known limitation.

## GAP-11 — Direct DecisionPipeline callers bypass validate_request

- Observation: `runtime/decision.py` `propose` accepts arbitrary dicts;
  only the web layer calls `sandbox.validate_request`. Direct callers are
  still fail-closed by policy: unknown actions/namespaces resolve to
  `DENY_ALL_CONTEXT` and are clean DENY (asserted by
  `test_unknown_action_is_denied`).
- Classification: NO_ACTION (policy backstop already fail-closed; defense in
  depth exists; not a v0.3.0 change)

## GAP-12 — Denial evidence recording swallows ledger exceptions

- Observation: `src/mgk/executor.py` `_record_denial` catches
  `BaseException` to best-effort persist denial records. Audit/failure/state
  integrity pre-checks run before every execution and fail closed on
  pre-existing corruption.
- Classification: NO_ACTION (fail-closed on pre-checks; best-effort denial
  recording is deliberate and documented)

## GAP-13 — consumed_nonces table grows without pruning

- Observation: `security.sqlite` consumed-nonce table is never pruned.
- Classification: NO_ACTION (storage concern, not authority; bounded by the
  closed actuator rate; recorded as a known limitation)

## GAP-14 — 8 MiB resource-create cap not reachable via public flow

- Observation: `authority.py` MAX_RESOURCE_BYTES (8 MiB) create-size check is
  unreachable because canonical payloads are capped at MAX_CANONICAL_BYTES
  (256 KiB). Effective bound is stricter (256 KiB), which is fail-closed in
  the safe direction.
- Classification: NO_ACTION (safe direction; documented in
  `tests/test_mutation_v3_security.py`)

## GAP-15 — Root manifest external anchor not modified by candidate

- Observation: v0.3.0 does not modify the protected TCB tree
  (contracts/ROOT_MANIFEST.sha256, orchestrator/tcb/*, gates/protected/*,
  .github/workflows/*). Protected-path hashes remain valid; no external
  anchor transition is required.
- Classification: NO_ACTION (NEXT_ROOT_MANIFEST_SHA256=UNCHANGED)

---

## Gap resolution summary

| Gap | Class | v0.3.0 disposition |
|-----|-------|--------------------|
| GAP-01 | DOCUMENTATION_GAP/ARCHITECTURE_MISMATCH | RESOLVED (boundary doc) |
| GAP-02 | DOCUMENTATION_GAP | RESOLVED (scope contract) |
| GAP-03 | DOCUMENTATION_GAP | RESOLVED (version bump) |
| GAP-04 | SECURITY_GAP | RESOLVED (durable human-gate state machine) |
| GAP-05 | TEST_GAP | RESOLVED (red-team probes A23-A25) |
| GAP-06 | TEST_GAP | RESOLVED (discriminating tests) |
| GAP-07 | DOCUMENTATION_GAP | DOCUMENTED (mutation population scope) |
| GAP-08 | NO_ACTION | DOCUMENTED (known limitation) |
| GAP-09 | NO_ACTION | DOCUMENTED |
| GAP-10 | NO_ACTION | DOCUMENTED (known limitation) |
| GAP-11 | NO_ACTION | DOCUMENTED |
| GAP-12 | NO_ACTION | DOCUMENTED |
| GAP-13 | NO_ACTION | DOCUMENTED (known limitation) |
| GAP-14 | NO_ACTION | DOCUMENTED |
| GAP-15 | NO_ACTION | UNCHANGED (root manifest) |

No speculative complexity was introduced. Only GAP-01/02/03/04/05/06 drive
v0.3.0 changes.