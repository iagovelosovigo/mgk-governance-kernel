# MGK v0.2.0 — Integration & Browser Acceptance Evidence

- Evidence: `evidence/v0.2.0/integration/scenarios.json`,
  `evidence/v0.2.0/browser/browser_acceptance.json` + PNG screenshots
- Run: 2026-08-17 (local), loopback only
- Tools: `tools/scenarios_v2.py` (HTTP/CLI scenario runner),
  `tools/browser_acceptance_v2.py` (playwright headless chromium)

## Result

All scenarios A–J passed. Central invariant held throughout:
**PROPOSAL IS NOT AUTHORITY** — no governed side effect without a valid,
scoped, single-use capability.

| Scenario | What it proves | Result |
|---|---|---|
| A-lifecycle | `start`/`status`/`doctor`/`test`/`stop` | PASS |
| B-safe-read | safe read → ALLOW, capability issued, executed | PASS |
| C-sensitive-gated | write → REQUIRE_HUMAN, no capability, no side effect | PASS |
| D-human-approve | operator approve → ALLOW executed, signed | PASS |
| E-human-deny | operator deny → DENY, no side effect | PASS |
| F-traversal-denied | `../`, absolute path, `process.exec` → DENY | PASS |
| G-malformed-fail-closed | padded b64, missing content, missing file → fail closed | PASS |
| H-integrity-evidence | audit/flight heads, epoch, nonce count, authority id | PASS |
| I-flight-integrity | flight recorder events recorded | PASS |
| J-persistence-restart | decisions + keys survive stop/start | PASS |

## Browser acceptance (playwright, headless chromium)

- Pages verified + screenshotted: `/` (status), `/propose`, `/human-gate`,
  `/flight-recorder`, `/evidence` — all render, all `ok=True`.
- Interactive flow: submitting a `sandbox.write_file` proposal from the
  browser returned `REQUIRE_HUMAN` (no capability, no side effect); the human
  gate page listed the pending proposal.
- Screenshots: `index.png`, `propose.png`, `human_gate.png`,
  `human_gate_pending.png`, `flight_recorder.png`, `evidence.png`,
  `propose_result_require_human.png`.

## Reused command details

- Scenario runner run under the project venv python (cryptography/pytest env).
- Browser runner run under framework Python 3.14.4 (playwright + chromium cache).
- Server: `python -m runtime.server start --workdir <tmp> --port 8811/8812`,
  health-polled to `running` before scenario execution.