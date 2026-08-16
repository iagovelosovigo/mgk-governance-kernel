# MGK v0.2.0 — Discovery Report

- **Date**: 2026-08-16T22:31:08Z
- **Generator**: mgk-autopilot/v0.2.0-functional-runtime
- **Baseline**: main @ `130606b3f403e22e5c9b85a467a3012fe83da381` (tree `70fcc64e27d4db541d7f874fba038689e7eb8373`), tag `v0.1.0` present.
- **Machine-readable**: see `discovery.json` (schema `mgk.v0.2.0.discovery.v1`).

## 1. Baseline identity

Git-verified v0.1.0 identity: tag `v0.1.0` -> commit `130606b3…` (merge of PR #7), tree `70fcc64e27d4db541d7f874fba038689e7eb8373`. The master prompt states tree `70fcc642e7d4db541d7f874fba038689e7eb8373`; this is a transcription error at positions 8–9 (`2e` vs `e2`). Fail-closed discrepancy reported; **git-derived identity is authoritative**.

## 2. Environment

- macOS (darwin), 8 CPUs, 8 GB RAM.
- Default `python3` = `/opt/homebrew/bin/python3` (3.14.6); venv + pip 26.1.2 available.
- Playwright importable via framework Python 3.14.4; Chromium cached (`chromium-1208`, headless shell), Google Chrome installed. Node v24.15.0.
- No project service currently listening; loopback ports free.

## 3. Existing kernel (reuse)

`muda-governance-kernel` v0.1.0, src layout, single dependency `cryptography==46.0.0`, single entry point `mgk = mgk.cli:main` (only subcommand `h14-smoke`).

Reusable modules (src/mgk):
- `authority.py` — `CapabilityAuthority.issue`: SAXP-gated, binds epoch + nonce + resource binding, signs envelope. The only mintage point.
- `verifier.py` — `CapabilityVerifier.verify`: strict canonical parse, exact payload key set, epoch check, atomic nonce consumption (single-use).
- `executor.py` — `CapabilityExecutor.execute`: ledger+state integrity pre-checks, verify, pre-commit epoch re-check, bound resource ops, post-effect audit with rollback on `resource.create`.
- `saxp.py` — three-valued `TEN_XEITO / REQUIRE_XEITO / NON_TEN_XEITO`.
- `ledger.py` — hash-chained signed-checkpoint `AuditLedger`/`FailureLedger`.
- `state.py` — SQLite WAL `SecurityState`: signed epoch envelope with rollback floor, atomic nonce consumption.
- `resource.py` — descriptor-based (`openat`, `O_NOFOLLOW`) `ResourceGuard` with bind_at_issue / revalidate_at_commit anti-TOCTOU.
- `crypto.py`, `canonical.py`, `models.py`, `cha.py`, `arrow.py`, `feedback.py`, `clock.py`, `errors.py`.

## 4. Key finding: no web layer

There is **zero HTTP/socket/web code** in the repo. `mgk.cli.main` handles only `h14-smoke`. All HTTP infrastructure for `./mgk start` is net-new. Decision: **stdlib-only HTTP server** bound to `127.0.0.1` to avoid adding dependencies (minimizes mutation surface and clean-install friction).

## 5. Decision state mapping (design basis)

- **ALLOW** = SAXP `TEN_XEITO` + verifier success -> execution.
- **DENY** = SAXP `NON_TEN_XEITO` or any verification/execution denial -> no execution + denial observable.
- **REQUIRE_HUMAN** = SAXP `REQUIRE_XEITO` (critical uncertainty / incomplete info / low sentidino) -> queued for human gate.
- **INDETERMINATE** = unexpected exception / integrity failure / cannot determine -> **fail-closed DENY**, no side effect.

## 6. Sandbox actuators

Reuse the `ResourceGuard` bind-at-issue/revalidate-at-commit pattern. Add a closed actuator registry in `runtime/sandbox/`:
`read_file`, `write_file`, `append_file`, `create_record`, `read_record` — all confined to the runtime workspace root, defending against `..`, absolute paths, symlink escape, and TOCTOU swaps.

## 7. Capability binding

v0.1.0 capability payload already binds request id (`request_digest`), action (scope), resource (resource_binding), constraints (TTL/max TTL), issuance time (`issued_at`), expiry (`expires_at`), nonce (single-use, atomically consumed), plus `authorization_epoch`. This is exactly the requirement; the runtime will surface and exercise it.

## 8. Test / gate assets to preserve and reuse

- Repo tests: `tests/` (24 files) incl. `test_h14.py`, `test_capabilities.py`, `test_resources.py`, `test_concurrency.py`, `test_audit.py`.
- Independent frozen exam: 59 tests, 8 suites, `independent_exam/` with `tools/` (run_exam, evaluate_acceptance, clean_install, reproducibility, mutation_check, check_frozen), `FUNCTIONAL-ACCEPTANCE.yaml`, `FROZEN.sha256`.
- Red team: `redteam/` 41 vectors, 19 attacks (18 critical), 15 invariants, `run_attacks.py` (per-vector subprocess stdin/stdout adapter contract).
- Mutation gate v2: `tools/mutation_gate_v2.py` + `mutation_classifier_v2.py`, threshold 0.90, FAIL_CLOSED on INDETERMINATE.
- TCB: `orchestrator/tcb/` root-of-trust manifest + gate result checks; `contracts/` frozen YAML contracts + `ROOT_MANIFEST.sha256`.

## 9. Secrets

No committed secrets. All `private_key` occurrences are runtime-generated test/authority fixtures. `OPENAI_API_KEY` is a CI Actions placeholder.

## 10. Constraints honored

Loopback-only; no secrets; closed actuator registry (no arbitrary shell/fs/network); no eval/exec of untrusted content; never weaken v0.1.0 tests/contracts/Root of Trust; branch `mgk-autopilot/v0.2.0-functional-runtime` only; v0.1.0 tag and main history immutable; FAIL_CLOSED on INDETERMINATE; final human release gate (no merge/tag/release).

## 11. Conclusion

Discovery complete. v0.1.0 kernel is a clean, injectable object graph directly reusable as the authority core of the v0.2.0 Functional Governance Runtime. All web/CLI/sandbox-actuator/human-gate components are net-new and will be implemented on top without weakening the existing contracts, tests, or root of trust.