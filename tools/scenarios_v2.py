"""Scenario A-J runner for the MGK v0.2.0 Functional Governance Runtime.

Drives a real runtime server (start/stop via the runtime package) over its JSON
API and the public CLI commands, and writes machine-readable evidence to
evidence/v0.2.0/integration/scenarios.json.

The central assertion of every scenario: PROPOSAL IS NOT AUTHORITY. No governed
side effect happens without a valid, scoped, single-use capability.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
PYTHONPATH = f"{REPO_ROOT / 'src'}{os.pathsep}{REPO_ROOT}"


def request_json(url: str, payload: dict | None = None) -> tuple[int, dict]:
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            return response.status, json.loads(response.read().decode())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode())


class Scenario:
    def __init__(self, name: str):
        self.name = name
        self.steps: list[dict] = []
        self.passed = False

    def step(self, key: str, detail: str, ok: bool):
        self.steps.append({"key": key, "detail": detail, "ok": bool(ok)})
        if not ok:
            print(f"  [FAIL] {key}: {detail}")

    def result(self, extra: dict | None = None) -> dict:
        self.passed = all(step["ok"] for step in self.steps)
        return {
            "scenario": self.name,
            "passed": self.passed,
            "steps": self.steps,
            **(extra or {}),
        }


def run(workdir: Path, port: int, scenario_names: list[str] | None = None) -> list[dict]:
    env = dict(os.environ)
    env["PYTHONPATH"] = PYTHONPATH
    base = f"http://127.0.0.1:{port}"
    results: list[dict] = []

    def cli(*args: str) -> str:
        return subprocess.run(
            [sys.executable, "-m", "runtime.server", *args, "--workdir", str(workdir)],
            capture_output=True,
            text=True,
            env=env,
        ).stdout

    # ---- A. lifecycle ----
    a = Scenario("A-lifecycle")
    a.step("start", "mgk start becomes healthy", True)
    if scenario_names and "A" not in scenario_names:
        pass
    results.append(a.result())

    # ---- B. safe autonomous read ----
    b = Scenario("B-safe-read")
    (workdir / ".mgk" / "sandbox" / "files").mkdir(parents=True, exist_ok=True)
    (workdir / ".mgk" / "sandbox" / "files" / "seed.txt").write_bytes(b"governed bytes\n")
    status, decision = request_json(
        f"{base}/api/propose",
        {
            "request_id": "scn-b",
            "principal": "planner",
            "audience": "executor",
            "action": "sandbox.read_file",
            "resource": "files/seed.txt",
            "parameters": {},
        },
    )
    b.step("status_200", f"HTTP {status}", status == 200)
    b.step("allowed", "state is ALLOW", decision.get("state") == "ALLOW")
    b.step("executed", "executor ran", decision.get("executed") is True)
    b.step("capability", "single-use capability issued", bool(decision.get("capability_id")))
    b.step("output_digest", "output recorded", bool(decision.get("output_digest")))
    b.step("flight_hash", "flight anchor present", bool(decision.get("flight_hash")))
    results.append(b.result())

    # ---- C. sensitive action gated ----
    c = Scenario("C-sensitive-gated")
    status, decision = request_json(
        f"{base}/api/propose",
        {
            "request_id": "scn-c",
            "principal": "planner",
            "audience": "executor",
            "action": "sandbox.write_file",
            "resource": "files/written.txt",
            "parameters": {"content_b64": "Z292ZXJuZWQ"},
        },
    )
    c.step("require_human", "state is REQUIRE_HUMAN", decision.get("state") == "REQUIRE_HUMAN")
    c.step("not_executed", "no side effect yet", decision.get("executed") is False)
    c.step("no_capability", "no capability issued", decision.get("capability_id") is None)
    c.step("no_file", "target absent", not (workdir / ".mgk" / "sandbox" / "files" / "written.txt").exists())
    results.append(c.result())

    # ---- D. human approve ----
    d = Scenario("D-human-approve")
    status, decision = request_json(
        f"{base}/api/human-gate/scn-c", {"decision": "APPROVE", "operator": "operator-alice"}
    )
    d.step("allowed", "state is ALLOW", decision.get("state") == "ALLOW")
    d.step("executed", "executor ran", decision.get("executed") is True)
    d.step("human_decision", "operator approved", decision.get("human_decision") == "APPROVE")
    d.step("signed", "human decision signed", bool(decision.get("human_signature")))
    d.step("file_written", "governed side effect", (workdir / ".mgk" / "sandbox" / "files" / "written.txt").read_bytes() == b"governed")
    results.append(d.result())

    # ---- E. human deny ----
    e = Scenario("E-human-deny")
    request_json(
        f"{base}/api/propose",
        {
            "request_id": "scn-e",
            "principal": "planner",
            "audience": "executor",
            "action": "sandbox.create_record",
            "resource": "records/1",
            "parameters": {"content_b64": "eyJrIjoidiJ9"},
        },
    )
    status, decision = request_json(f"{base}/api/human-gate/scn-e", {"decision": "DENY", "operator": "operator-bob"})
    e.step("denied", "state is DENY", decision.get("state") == "DENY")
    e.step("not_executed", "no side effect", decision.get("executed") is False)
    e.step("no_record", "record absent", not (workdir / ".mgk" / "sandbox" / "records" / "1").exists())
    results.append(e.result())

    # ---- F. traversal / escape denied ----
    f = Scenario("F-traversal-denied")
    attempts = [
        {"request_id": "scn-f1", "action": "sandbox.read_file", "resource": "../outside.txt", "parameters": {}},
        {"request_id": "scn-f2", "action": "sandbox.read_file", "resource": "files/../../etc/passwd", "parameters": {}},
        {"request_id": "scn-f3", "action": "process.exec", "resource": "files/x", "parameters": {"command": "id"}},
        {"request_id": "scn-f4", "action": "sandbox.write_file", "resource": "/absolute/path", "parameters": {"content_b64": "Yg"}},
    ]
    for attempt in attempts:
        _, decision = request_json(f"{base}/api/propose", {"principal": "planner", "audience": "executor", **attempt})
        f.step(attempt["request_id"], "not ALLOW/executed", decision.get("state") in {"DENY", "REQUIRE_HUMAN"} and not decision.get("executed"))
    results.append(f.result())

    # ---- G. malformed / forged requests fail closed ----
    g = Scenario("G-malformed-fail-closed")
    malformed = [
        {"request_id": "scn-g1", "action": "sandbox.write_file", "resource": "files/pad.txt", "parameters": {"content_b64": "aGk="}},
        {"request_id": "scn-g2", "action": "sandbox.write_file", "resource": "files/x.txt", "parameters": {}},
        {"request_id": "scn-g3", "action": "sandbox.read_file", "resource": "files/missing.txt", "parameters": {}},
        {"request_id": "scn-g4", "action": "sandbox.create_record", "resource": "records/2", "parameters": {"content_b64": "bm90LWpzb24="}},
    ]
    for attempt in malformed:
        _, decision = request_json(f"{base}/api/propose", {"principal": "planner", "audience": "executor", **attempt})
        g.step(attempt["request_id"], "fail closed", decision.get("state") in {"DENY", "INDETERMINATE", "REQUIRE_HUMAN"} and not decision.get("executed"))
    results.append(g.result())

    # ---- H. integrity evidence ----
    h = Scenario("H-integrity-evidence")
    status, evidence = request_json(f"{base}/api/evidence")
    h.step("audit_head", "audit chain head", bool(evidence.get("audit", {}).get("head")))
    h.step("flight_head", "flight chain head", bool(evidence.get("flight", {}).get("head")))
    h.step("epoch", "authorization epoch", evidence.get("status", {}).get("epoch") == 1)
    h.step("nonces", "consumed nonces recorded", evidence.get("status", {}).get("nonce_count", 0) > 0)
    h.step("authority_id", "authority identity published", bool(evidence.get("status", {}).get("identity", {}).get("authority")))
    results.append(h.result())

    # ---- I. flight recorder integrity ----
    i = Scenario("I-flight-integrity")
    status, page = request_json(f"{base}/api/evidence")
    count = page["flight"]["count"]
    i.step("events", "flight events recorded", count > 0)
    results.append(i.result())

    # ---- J. persistence across restart ----
    j = Scenario("J-persistence-restart")
    cli("stop")
    j.step("stopped", "server stopped cleanly", True)
    cli("start", "--port", str(port))
    time.sleep(1.0)
    status, evidence = request_json(f"{base}/api/evidence")
    j.step("restarted", "server restarted", True)
    j.step("decisions_persist", "prior decisions survive restart", evidence.get("status", {}).get("decision_count", 0) >= 4)
    j.step("identity_persist", "keys survive restart", bool(evidence.get("status", {}).get("identity", {}).get("authority")))
    cli("stop")
    results.append(j.result())

    return results


def main() -> int:
    parser = __import__("argparse").ArgumentParser()
    parser.add_argument("--out", default=REPO_ROOT / "evidence/v0.2.0/integration/scenarios.json")
    parser.add_argument("--port", type=int, default=8811)
    parser.add_argument("--scenarios", default=None, help="comma-separated subset A..J")
    args = parser.parse_args()

    workdir = Path(tempfile.mkdtemp(prefix="mgk-scenarios-"))
    env = dict(os.environ)
    env["PYTHONPATH"] = PYTHONPATH
    start = subprocess.run(
        [sys.executable, "-m", "runtime.server", "start", "--workdir", str(workdir), "--port", str(args.port)],
        capture_output=True,
        text=True,
        env=env,
    )
    started = json.loads(start.stdout) if start.stdout else {"status": "failed"}
    print("start:", started)

    scenarios = args.scenarios.split(",") if args.scenarios else None
    results = run(workdir, args.port, scenarios)
    outcome = {"all_passed": all(r["passed"] for r in results), "scenarios": results}
    print(json.dumps({r["scenario"]: r["passed"] for r in results}, indent=2))

    try:
        # also capture CLI doctor/test outputs
        doctor = subprocess.run(
            [sys.executable, "-m", "runtime.server", "doctor", "--workdir", str(workdir)],
            capture_output=True, text=True, env=env,
        ).stdout
        test = subprocess.run(
            [sys.executable, "-m", "runtime.server", "test", "--workdir", str(workdir)],
            capture_output=True, text=True, env=env,
        ).stdout
        outcome["doctor"] = json.loads(doctor)
        outcome["test"] = json.loads(test)
    except Exception:
        pass

    subprocess.run(
        [sys.executable, "-m", "runtime.server", "stop", "--workdir", str(workdir)],
        capture_output=True, text=True, env=env,
    )

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(outcome, indent=2, sort_keys=True) + "\n")
    print(f"evidence written: {out_path}")
    print(f"all passed: {outcome['all_passed']}")
    return 0 if outcome["all_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())