# Dependency Freeze — v0.2.0 Functional Governance Runtime

Generated: 2026-08-17 from clean venv A (see `clean-install-ab.md`).

## Pinned runtime + test dependencies (requirements.lock)

| Package | Pinned |
|---|---|
| cryptography | 46.0.0 |
| hypothesis | 6.138.13 |
| pytest | 8.4.1 |
| pytest-timeout | 2.4.0 |

`pyproject.toml` declares runtime dependency `cryptography==46.0.0`, matching
the lock. Build backend pins `setuptools==75.8.0`, `wheel==0.45.1`.

## Full transitive freeze (clean venv A, `pip freeze`)

```
attrs==26.1.0
cffi==2.1.1
cryptography==46.0.0
hypothesis==6.138.13
iniconfig==2.3.0
muda-governance-kernel @ file://<repo>
packaging==26.3
pluggy==1.6.0
pycparser==3.0
Pygments==2.20.0
pytest-timeout==2.4.0
pytest==8.4.1
setuptools==75.8.0
sortedcontainers==2.4.0
wheel==0.45.1
```

Verified identical between clean venv A and clean venv B (reproducible install).

## Secret scan

Patterns scanned across the working tree AND git-tracked content
(`git grep`), excluding campaign-artifact dirs (evidence/, redteam/,
independent_exam/):

- PEM/SSH/EC/RSA private-key blocks: none
- AWS access key (`AKIA…`): none
- GitHub token (`ghp_…`): none
- OpenAI-style `sk-…` (24+ chars): none
- Slack token (`xox…`): none
- Google API key (`AIza…`): none
- `password=…`/`secret=…`/`token=…`/`api_key=…` assignments in source: none
- `*.pem` / `*.key` / `*.p12` / `*.env` files in tree: none

No secrets present in the candidate tree. Runtime authority keys are
generated at runtime per workspace (never committed); see
`runtime/workspace.py` `_load_or_generate_key`.