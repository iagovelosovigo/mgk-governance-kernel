# Phase 14/15 — Functional Delivery Package + Delivery Smoke (v0.2.0)

Date: 2026-08-17
Repo: `mgk-autopilot/v0.2.0-security-mutation-adequacy`
Commit: `0028e27` (post-freeze), source tree = tested Phase 8–12 code.

## 1. Delivery artifacts (built from the campaign tree)

`dist/muda_governance_kernel-0.2.0-py3-none-any.whl` (50,975 bytes)
`dist/muda_governance_kernel-0.2.0.tar.gz` (74,997 bytes)

Built with `python -m build` (setuptools==75.8.0, wheel==0.45.1). The wheel
contains `mgk` (20 modules), `runtime` (incl. sandbox), `candidate_adapter.py`,
`exam_hypothesis_profile.py`, entry point `mgk = mgk.cli:main`.

### Wheel integrity vs campaign source

- `runtime/workspace.py` in the wheel contains the Phase-11 hardening
  (`os.chmod(..., 0o700)` and `os.chmod(path, 0o600)`): TRUE
- Wheel `runtime/workspace.py` sha256 == source `runtime/workspace.py`: MATCH

## 2. Delivery smoke (fresh venv, wheel install, clean workdir)

Installed wheel in a fresh Python 3.12 venv; dependency `cryptography 46.0.0`;
package `muda-governance-kernel 0.2.0`.

| Check | Result |
|---|---|
| `mgk --help` | lists h14-smoke/start/stop/status/doctor/test |
| `mgk start --workdir <fresh>` | running, version 0.2.0, port 8787 |
| `mgk doctor` | PASS (all 7 checks) |
| `mgk test` | PASS (`h14_proposal_is_not_authority: true`) |
| `mgk h14-smoke` | PASS (0 forbidden executions) |
| `mgk stop` | stopped |
| Live `.mgk` perms | `.mgk` 0700, `keys/` 0700, key/state files 0600 |

## 3. Full suite against the wheel install

The 408-test suite was re-run with the package installed into a fresh venv from
the wheel (installed-only, no source-tree runtime dependency):

| Suite | Result |
|---|---|
| tests/ (installed wheel, 408 tests) | 408 passed |

## Conclusion

The functional delivery package builds cleanly from the frozen campaign tree,
is byte-consistent with the hardened source, installs with the pinned
dependency, and passes the complete delivery smoke (`doctor`, `test`,
`h14-smoke`) plus the full 408-test regression suite from the installed wheel.