# Delivery Package & Installed-Wheel Smoke (v0.3.0 publishable-candidate)

Date: 2026-08-17
Repo commit: `0058512` (working tree at build time)
Builder: `python -m build` 1.2.2.post1 in a fresh venv, build isolation using the
pinned backend `setuptools==75.8.0, wheel==0.45.1`.
Stale v0.2.0 `dist/` artifacts were moved aside before building.

## Artifacts

| Artifact | Path | SHA-256 | Bytes |
|---|---|---|---|
| Wheel | `dist/muda_governance_kernel-0.3.0-py3-none-any.whl` | `de63848a8346e728dc293aacda7d22a9f5909240a8fa12b8f14775b0802cb5ab` | 51529 |
| Sdist | `dist/muda_governance_kernel-0.3.0.tar.gz` | `b0c739adbbbfb81c7bda7640553514b3af9b86d1c41be77fa8073af4dd5e56f9` | 76294 |

Installed-content equivalence to source (sha256 match):

- `runtime/workspace.py` (installed vs `runtime/workspace.py`): identical
- `mgk/__init__.py` (installed vs `src/mgk/__init__.py`): identical

## Delivery smoke (fresh venv, CPython 3.12.13, `pip install dist/*.whl`)

| Check | Result |
|---|---|
| Installed package | muda-governance-kernel 0.3.0 (cryptography 46.0.0) |
| `mgk --help` | PASS |
| `mgk start --workdir …` | PASS (version 0.3.0, running) |
| `mgk doctor --workdir …` | PASS (7/7 checks) |
| `mgk test --workdir …` | PASS (`h14_proposal_is_not_authority: true`) |
| `mgk h14-smoke` | PASS (0 forbidden executions) |
| `mgk stop --workdir …` | PASS |
| Live permissions | workspace root 0700, `.mgk` 0700, key/state files 0600 |

## Installed-wheel suite

Mode: installed-only. The source tree copy has NO top-level `runtime/`, so both
`mgk` and `runtime` resolve from the installed wheel in site-packages.

Result: **415 passed**.

## Conclusion

The delivery package builds cleanly from the v0.3.0 candidate, installs with
pinned dependencies, passes the full CLI smoke and the 415-test suite from the
installed wheel, and its installed content is byte-identical to the source.