# Clean Install A/B — Reproducibility (v0.3.0 publishable-candidate)

Date: 2026-08-17
Interpreter: CPython 3.12.13 (`/opt/homebrew/Cellar/python@3.12/3.12.13_2`)
Build backend: setuptools==75.8.0, wheel==0.45.1 (as pinned in pyproject.toml)
Source tree: rsync copy of the working tree at commit `0058512`
  (`mgk-verify/ab-v03/repo`, excluding `.git`, `__pycache__`, `*.pyc`, `.mgk`,
  `/dist`, `/*.egg-info`, top-level `/mgk`).
Full suite at the time of this run: **415 tests**.

## Procedure

1. Two fresh venvs created from the same interpreter: `venv-a`, `venv-b`.
2. Each installed the package NON-editable: `pip install <repo>` plus the
   pinned test deps (pytest 8.4.1, hypothesis 6.138.13, pytest-timeout 2.4.0).
3. Full suite run from `<repo>` in each venv.
4. To prove the install is self-contained, the top-level `runtime/` source
   directory was temporarily moved aside in the copied tree and the full suite
   was re-run against the installed `runtime` from site-packages.
5. Installed site-packages `mgk` and `runtime` trees hashed (sha256, .py only)
   and compared across A and B.

## Results

| Check | Result |
|---|---|
| Installed version | 0.3.0 (both venvs) |
| Suite in venv A | 415 passed |
| Suite in venv B | 415 passed |
| Suite in venv A, top-level `runtime/` source removed (installed-only) | 415 passed |
| `import mgk` resolves to site-packages | yes (`.../site-packages/mgk/__init__.py`) |
| `import runtime` resolves to site-packages | yes (`.../site-packages/runtime/__init__.py`) |
| site-packages `mgk` tree hashes A vs B | identical (17 files) |
| site-packages `runtime` tree hashes A vs B | identical (10 files) |
| Installed dependency versions A vs B | identical (cryptography 46.0.0) |
| pytest / hypothesis / pytest-timeout A vs B | identical (8.4.1 / 6.138.13 / 2.4.0) |

Hash files: `installed-tree-A.sha`, `installed-tree-B.sha` (sha256 over all
`.py` files in the installed `mgk` and `runtime` trees, sorted).

## Conclusion

A clean, non-editable install of the v0.3.0 candidate tree at `0058512` is
reproducible: two independent fresh environments produce byte-identical
installed packages and identical full-suite outcomes (415 passed), with no
dependency on the source tree at runtime.