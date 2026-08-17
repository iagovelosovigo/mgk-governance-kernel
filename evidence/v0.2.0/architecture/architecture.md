# MGK v0.2.0 — Functional Governance Runtime: Architecture

- Status: `ARCHITECTURE_APPROVED`
- Schema: `mgk.v0.2.0.architecture.v1`
- Branch: `mgk-autopilot/v0.2.0-functional-runtime`
- Related: `architecture.json` (machine-readable), `discovery.json`, `baseline.json`

## Objective

A real, browser-usable governance runtime exposing the core MGK security model as a
web application on loopback (`127.0.0.1:8787`), exercising the real kernel
(`src/mgk`) — not a simulation. Central invariant carried through every layer:

> **PROPOSAL IS NOT AUTHORITY** — a proposal is data only. No governed side
> effect occurs without a valid, scoped, single-use capability issued by the
> kernel authority and executed by the kernel executor.

## Design constraints (from discovery + frozen contracts)

- Kernel `AuthorityPolicy` default (`allowed_actions == {resource.read, resource.create}`)
  MUST NOT change: asserted by `test_mutation_v2_contracts.py:227`.
- `h14-smoke` result dict and `_safe_context` MUST NOT change:
  asserted by `test_mutation_v2_cli.py`.
- Frozen/protected files (`contracts/`, `candidate_adapter.py`,
  `exam_hypothesis_profile.py`, `gates/protected/`, `independent_exam/FROZEN.sha256`,
  `orchestrator/tcb/`, `.github/workflows/`) are byte-immutable.
- `src/mgk/*` is modifiable but every change is **additive**: existing binding
  shapes and error strings are unchanged for `resource.*` actions; new sandbox
  actions branch alongside.
- Loopback only; no secrets in the repo; no arbitrary shell/fs/network actuators;
  no eval/exec of untrusted content.

## Layered design

### 1. Kernel extensions (additive, in `src/mgk`)

- `crypto.py`: new domain separator `HUMAN_GATE_DOMAIN = b"MGK-HUMAN-GATE-V1\x00"`
  for operator-signed human decisions.
- `resource.py`: new descriptor-based, anti-TOCTOU operations
  `bind_write`/`write_bound` (create-or-overwrite with `O_EXCL` + `O_NOFOLLOW`),
  `bind_append`/`append_bound`. Pre-state verified before mutation; post-state
  verified after; `fsync` on file and parent; rollback of created file on failure.
- `authority.py`: `SANDBOX_ACTIONS` frozen set
  `{sandbox.read_file, sandbox.write_file, sandbox.append_file,
   sandbox.create_record, sandbox.read_record}`; `_bind_resource` branches for the
  five sandbox actions (resource.* branches byte-unchanged); `issue()` gains an
  optional `context=` override so an operator-approved request can be issued
  under the resolved context (additive; existing callers unchanged).
- `verifier.py`: `_validate_payload` accepts the new binding shapes
  (`present`, `absent`, `write`, `append`); existing branches unchanged;
  unknown actions still raise `ScopeError("unsupported capability action")`.
- `executor.py`: dispatches the five sandbox actions through the guarded
  read/write/append/create bound operations; `create_record` rolls back on
  `EXECUTION_COMPLETED` failure like `resource.create`.

### 2. Runtime package (`runtime/`)

- `config.py`: `RuntimeConfig` (workdir, host 127.0.0.1, port 8787, ttl 60,
  epoch 1) with validation.
- `workspace.py`: `Workspace` builds the full object graph (SecurityState,
  ResourceGuard rooted at sandbox/, AuditLedger, FailureLedger, FlightRecorder,
  RuntimeLedger, RuntimePolicy, CapabilityAuthority/Verifier/Executor,
  DecisionPipeline). Keys (`authority.key`, `audit.key`, `operator.key`) are
  generated locally with mode 0600; identities published as `*.pub`. Everything
  lives under `workdir/.mgk/` (gitignored).
- `policy.py`: `RuntimePolicy` modes `allow_safe`/`deny_all`/`require_human`;
  closed action set = `SANDBOX_ACTIONS | {resource.read, resource.create}`;
  resource prefixes `files/`, `records/`, `workspace/`; sensitive actions
  (`write_file`, `append_file`, `create_record`) force the human gate. Context
  selection maps policy violations to `DENY_ALL_CONTEXT` (clean DENY).
- `flight.py`: hash-chained JSONL flight recorder with checkpoints and
  `verify_integrity()`.
- `runtime_ledger.py`: SQLite (WAL) queryable index of proposals, decisions
  (one row per request, upserted as a proposal transitions), human actions.
  Trust lives in the signed ledgers + flight recorder, not this index.
- `decision.py`: `DecisionPipeline.propose` — validate → record → SAXP →
  `NON_TEN_XEITO` DENY / `REQUIRE_XEITO` REQUIRE_HUMAN / `TEN_XEITO` issue+execute.
  Deterministic denials (MGKError at issue time) are clean DENY, not
  INDETERMINATE. `human_approve`/`human_deny` record operator-signed decisions
  (`HUMAN_GATE_DOMAIN`), then approve issues under the resolved context.
  INDETERMINATE is reserved for genuinely unexpected exceptions (fail-closed).
- `sandbox/__init__.py`: closed actuator registry mapping the five actions to
  namespaces + validation of proposal shape.
- `server.py`: lifecycle `start|stop|status|doctor|test|serve`. Detached start
  launches `python -m runtime.server serve` with the repo `src`+root on
  `PYTHONPATH`, polls `/api/health` until running, persists pid/port files.
- `web.py`: stdlib `ThreadingHTTPServer` bound to loopback. HTML pages:
  `/` status, `/propose` form, `/human-gate`, `/decision/<id>`,
  `/flight-recorder`, `/evidence`. JSON API: `/api/status`, `/api/propose`,
  `/api/human-gate/<id>/approve|deny`, `/api/evidence`, `/api/health`.

### 3. CLI and launcher

- `src/mgk/cli.py` gains `start|stop|status|doctor|test` subcommands
  (lazy `runtime` import); `h14-smoke` and its exact output are untouched.
- `./mgk` launcher script at repo root (uses repo `src`, prefers `.venv`).

## Decision flow

```
proposal (data only)
   │ validate_request (closed actuator registry)
   v
record proposal ─────────────────────────────► runtime_ledger (index)
   │
   v
RuntimePolicy.context_for ──► SAXPContext
   │                                  │
   │ out of policy / deny_all         │ sensitive / require_human
   v                                  v
DENY_ALL_CONTEXT              REQUIRE_HUMAN_CONTEXT
   │                                  │
   v                                  v
SAXP ──► NON_TEN_XEITO        SAXP ──► REQUIRE_XEITO ──► REQUIRE_HUMAN ──► human gate
   │                                  (no side effect)      │ operator signs + approves
   v                                                         v
DENY                                              resolved context → issue → execute → ALLOW/DENY
   │
SAXP ──► TEN_XEITO ──► authority.issue (scoped, single-use capability)
                              │
                              v
                  executor.execute ──► guarded bound op ──► side effect (sandbox only)
                              │
                              v
                  audit ledger (hash chain) + flight recorder + runtime_ledger
```

## Persistence layout (all under `workdir/.mgk/`)

```
keys/                 authority.key|pub, audit.key|pub, operator.key|pub (0600)
security.sqlite       SecurityState (epoch, consumed nonces, WAL)
audit.jsonl           signed hash-chained execution audit + checkpoint
failures.jsonl        signed hash-chained failure ledger + checkpoint
flight.jsonl          hash-chained event recorder + checkpoint
runtime.sqlite        queryable proposal/decision/human-action index (WAL)
sandbox/files/        governed file namespace
sandbox/records/      governed record namespace
runtime.pid/.port     server lifecycle state
runtime.log           server log (0600)
```

## Integrity model

- Capability payload is signed (Ed25519, `CAPABILITY_DOMAIN`), scoped
  (action/resource), non-replayable (single-use nonce consumed in
  `SecurityState`), time-bounded (TTL), and bound to the request digest.
- Audit and failure ledgers are hash-chained checkpoints; flight recorder is
  hash-chained JSONL. `doctor` verifies all chains + epoch + state integrity.
- Human decisions are signed by the operator key under `HUMAN_GATE_DOMAIN`.

## Security controls

- Loopback bind only; no external network surface.
- No arbitrary command/fs/network actuators — a closed registry of five actions.
- Path traversal blocked by descriptor-based resolution (`O_NOFOLLOW`, no `..`,
  depth limit, root confinement).
- Fail-closed: unexpected exceptions → INDETERMINATE; deterministic violations → DENY.
- Keys generated locally, never stored in the repo; `.mgk/` gitignored.

## Versioning

- `pyproject.toml` stays `0.1.0` (frozen v0.1.0 exam tooling asserts this);
  the runtime reports its own `RUNTIME_VERSION = "0.2.0"` via `/api/status`
  and `/api/health`.

## Verification status

- Kernel regression: 284 tests pass (with additive sandbox extensions) against
  repo `src`.
- Runtime suite: 14 tests pass (workspace, decision states, human gate, flight
  integrity, ledgers, actuator registry, config validation).
- Root of Trust: `MGK_ROOT_MANIFEST_SHA256=4c309aad… python3 orchestrator/tcb/trust.py`
  → "Protected tree verified." (src/mgk edits are outside the protected set).
- Lifecycle: `start` (detached, health-polled) / `status` / `doctor` (PASS) /
  `test` (PASS) / `stop` verified; web flow (propose → REQUIRE_HUMAN →
  approve → ALLOW executed) verified end-to-end.