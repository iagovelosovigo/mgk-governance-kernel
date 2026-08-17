# MGK v0.2.0 — Red Team Evidence

- Evidence: `evidence/v0.2.0/redteam/redteam.json`
- Tool: `tools/redteam_v2.py`
- Run: 2026-08-17 (local), loopback only, ephemeral port
- Result: **all 14 attacks PASS** (no governed side effect without a valid,
  scoped, single-use capability; no undetected tampering)

## Attack set

| ID | Attack | Outcome |
|---|---|---|
| R1-csrf | cross-origin proposal (evil Origin) | DENY (403) — same-origin enforcement added |
| R1-sameorigin | same-origin proposal | gated normally |
| R2-symlink | symlink to /etc/passwd inside sandbox | DENY (RESOURCE_ERROR) |
| R3-append-gate | append to existing file | REQUIRE_HUMAN (sensitive) |
| R4-approve-missing | approve a proposal that never existed | INDETERMINATE (PROPOSAL_NOT_FOUND), fail-closed |
| R5-double-approve | approve the same proposal twice | single execution only |
| R6-nonce-replay | identical proposals | distinct single-use capabilities, nonce count grows |
| R7-flight-tamper | tamper `flight.jsonl` | /api/evidence returns structured 500 |
| R8-audit-tamper | append to `audit.jsonl` | `doctor` → FAIL (audit_integrity) |
| R9-key-perms | private key mode | 0600 |
| R10-oversize | >8 MiB write payload | fail-closed (INDETERMINATE) |
| R11-unknown-action | `sandbox.execute` | DENY (closed registry) |
| R12-deny-mode | deny_all mode | verified in test suite |
| R13-absolute | absolute resource path | DENY |
| R14-malformed-body | non-mapping parameters | DENY (400) |

## Remediations applied during this phase

1. **CSRF / cross-origin**: `runtime/web.py` now rejects state-changing
   `POST` requests whose `Origin`/`Referer` does not match the runtime
   origin (loopback + port). A hostile web page can no longer submit
   proposals to the local runtime.
2. **Structured fail-closed evidence**: `/api/evidence` and the `/evidence`
   page previously dropped the connection when a ledger's integrity chain
   was broken. They now return a structured 500 (JSON) / an HTML page naming
   the failed check — integrity failure is explicit, not silent.

## Post-attack verification

- `doctor` → PASS (all checks), `test` → PASS after the attack set was
  replayed on a clean workspace (integrity chains intact after restore).