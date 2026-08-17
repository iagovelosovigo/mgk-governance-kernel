# Phase 13 — Freeze & Sign Evidence (v0.2.0 Security-Mutation-Adequacy Campaign)

Date: 2026-08-17
Repo: `mgk-autopilot/v0.2.0-security-mutation-adequacy`
Commit: `2dfb4f7` (tree `8bfb145`), clean worktree at freeze time.

## What was frozen

`evidence/v0.2.0/release/freeze-security-mutation-adequacy.json`:

- `manifest`: 27 evidence files (security-mutation-adequacy 19, redteam 3,
  install 3, independent-exam 2), each with a SHA-256 digest, bound to the
  campaign git commit/tree.
- `signer_public_key`: `ed25519:7acf7dbe…edcc` (runtime-generated Ed25519 key;
  public key bytes and signature recorded; private key ephemeral, never stored).
- `signature`: Ed25519 over `json.dumps(manifest, sort_keys=True,
  separators=(",",":"))` with domain `MGK-FREEZE-V1\0`.

## Verification

`tools/security_mutation/verify_release_freeze.py`:

- Rehashes all 27 files against recorded digests — all match.
- Re-serializes the manifest exactly as signed and verifies the Ed25519
  signature against the recorded public key — valid.

Result: `verified: true`, `signature_valid: true`, 0 failures.

## Covered evidence

Phases 0–12 of this campaign: baseline, historical harness, Phase 1
population experiment + results, full population classification, sensitive
survivors + classification, Phase 4 discriminating-test verification, Phase 6
source audit, Phase 7 functional E2E, Phase 8 fresh population + addendum,
gate record (score 0.915510, PASS), Phase 9 red-team (33/33 adversarial),
Phase 10 clean-install A/B (407 tests), Phase 11 secrets/root-of-trust, Phase
12 independent verification exam.

The private key used to sign is ephemeral (generated at freeze time, never
persisted); the public key and signature are embedded in the freeze artifact,
making the signature independently re-verifiable from the artifact alone.