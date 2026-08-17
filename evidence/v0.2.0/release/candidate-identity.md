# MGK v0.2.0 — Final Candidate Identity

| Field | Value |
|---|---|
| VERSION | 0.2.0 |
| BRANCH | `mgk-autopilot/v0.2.0-functional-runtime` |
| FINAL_COMMIT_SHA | `1327e5e85a44b3a917a0472b7de2e6a202326c8b` |
| FINAL_TREE_SHA | `716527089f40ad881520d3944c01b238d8d3e862` |
| parent(s) | `bd36870e03f337ff567dd285e9c83685d650d3e9` |
| timestamp | 2026-08-17 |
| VERSIONED_WORKTREE_CLEAN | TRUE |
| untracked ephemeral files | none |
| baseline v0.1.0 commit | `130606b3f403e22e5c9b85a467a3012fe83da381` (tag v0.1.0) |
| baseline v0.1.0 tree | `70fcc64e27d4db541d7f874fba038689e7eb8373` |

## Provenance (candidate commits)

- `d3e1a6d` discovery evidence
- `2d0ae14` baseline snapshot + root-of-trust verification
- `edd3ea6` feat: implement functional governance runtime
- `9bc5e84` scenarios A–J + browser acceptance
- `5f069ad` red team v0.2.0, all 14 attacks pass
- `bd36870` fix: reconcile tested v0.2.0 resource runtime candidate (the tested O_RDWR tree)
- `1327e5e` chore: set MGK candidate version to 0.2.0 (FINAL_COMMIT)

The FINAL_COMMIT_SHA is the last commit that changes candidate code/metadata. The v0.1.0
baseline remains frozen at tag `v0.1.0` (`130606b`); no v0.1.0 history was modified.