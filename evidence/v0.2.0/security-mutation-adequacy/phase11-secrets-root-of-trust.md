# Phase 11 — Secrets & Root-of-Trust Review (v0.2.0)

Date: 2026-08-17
Repo: `a29e785` (+ Phase 11 hardening, uncommitted at write time)
Scope: re-scan of the candidate tree for secrets; audit of the authority
root-of-trust (key generation, storage, permissions, epoch, audit, human-gate
signatures) and defense-in-depth hardening of workspace permissions.

## 1. Secret scan (current tree)

Patterns scanned across the working tree (source, runtime, tools, tests,
contracts, orchestrator, candidate_adapter.py) and git-tracked content,
excluding campaign-artifact dirs (evidence/, redteam/, independent_exam/):

- PEM / OpenSSH / EC / RSA private-key blocks: none
- AWS access key (`AKIA…`), GitHub token (`ghp_…`), OpenAI-style `sk-…`,
  Slack token (`xox…`), Google API key (`AIza…`): none
- `password=` / `secret=` / `token=` / `api_key=` assignments in source: none
- `*.pem` / `*.key` / `*.p12` / `*.env` / `*.keystore` files in tree: none
- Git-tracked key/secret-like files (`git ls-files | grep .key/.pem/.env/...`): none
- Git-tracked private-key blocks (`git grep "BEGIN.*PRIVATE KEY"`): none

`.gitignore` excludes `.mgk/`, `.venv/`, build artifacts. Runtime authority
keys are generated locally per workspace (`Workspace._load_or_generate_key`,
Ed25519, O_EXCL create, 0600) and are never committed.

## 2. Root of trust

| Component | Finding |
|---|---|
| Key algorithm | Ed25519 (RFC 8032), `generate_private_key` from `mgk.crypto` |
| Private key storage | raw 32-byte, `os.open(path, O_WRONLY\|O_CREAT\|O_EXCL, 0o600)`, fsync |
| Key reuse / corruption | length check (32) + `load_private_key` strict validation |
| Identity | `ed25519:<sha256(pub)>` key ids written to `*.pub` |
| Epoch root of trust | `SecurityState` binds epoch to authority public key; epoch envelope signed with `EPOCH_DOMAIN`; tamper → `StateIntegrityError` |
| Nonce / replay | verifier consumes nonces; domain-separated signatures (AUDIT/EPOCH/HUMAN_GATE domains) |
| Audit ledger | `AuditLedger` checkpointed + signed; file mode 0600 (regression-tested) |
| Human gate | operator signature over proposal digest + decision with `HUMAN_GATE_DOMAIN` |
| Domain separation | `sign(key, domain, message)` = `key.sign(domain + message)`; separate domains per subsystem |
| Strict encoding | base64url canonicality enforced (no padding, no whitespace), size checks |

## 3. Phase 11 hardening (defense in depth)

Pre-fix observation (fresh workspace):
```
.mgk        0o755     (world-readable/traversable)
keys/       0o755     (directory listing reveals key names)
security.sqlite 0o644 (world-readable authorization state)
runtime.sqlite    0o644 (world-readable ledger incl. proposal parameters BLOB)
audit.jsonl 0o600     (already correct)
flight.jsonl 0o600    (already correct)
*.key       0o600     (already correct)
```

Hardening applied in `runtime/workspace.py` (outside the mutmut mutation
scope, so the Phase 8/9 full-population score remains valid):
- `.mgk` root and `keys/` directories are chmodded to **0700** (blocks
  unprivileged local traversal to sqlite WAL/SHM sidecars and key files).
- `security.sqlite` and `runtime.sqlite` are chmodded to **0600** after
  creation (the proposal `parameters` BLOB in the runtime ledger is
  potentially sensitive).

Regression test added:
`tests/test_runtime.py::test_workspace_hardens_directory_and_sqlite_permissions`.

## 4. Results

| Check | Result |
|---|---|
| Secret scan (working tree + git-tracked) | none found |
| Private key perms | 0600 |
| keys/ dir perm | 0700 (after fix) |
| .mgk root perm | 0700 (after fix) |
| state + ledger sqlite perm | 0600 (after fix) |
| Full suite | 408 passed |
| Phase 8/9 mutation population validity | unaffected (no src/mgk change) |

## Conclusion

The candidate tree contains no secrets; the root of trust is sound
(per-workspace Ed25519 authority, epoch envelope, signed/checkpointed audit,
domain-separated signatures, strict canonical encodings). The Phase 11 review
found and closed two defense-in-depth permission gaps (world-readable
`.mgk`/`keys` directories and sqlite stores), covered by a regression test.
No secrets, keys, or private material are committed or publishable.