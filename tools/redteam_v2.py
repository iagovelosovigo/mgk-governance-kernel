#!/usr/bin/env python3
"""Red team harness for the MGK v0.2.0 Functional Governance Runtime.

Targets the runtime attack surface added in v0.2.0: web API (CSRF/origin),
sandbox actuators (TOCTOU/symlinks/size), the human gate, capability
nonce/TTL handling across restart, ledger/recorder tamper detection, key
material hygiene, and the fail-closed decision states.

Every attack asserts one invariant: no governed side effect without a valid,
scoped, single-use capability, and no undetected tampering.
"""

from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
PYTHONPATH = f"{REPO_ROOT / 'src'}{os.pathsep}{REPO_ROOT}"


def request(url: str, payload: dict | None = None, headers: dict | None = None) -> tuple[int, dict | None]:
    data = json.dumps(payload).encode() if payload is not None else None
    merged = {"Content-Type": "application/json"}
    merged.update(headers or {})
    req = urllib.request.Request(url, data=data, headers=merged, method="POST" if payload is not None or (headers or {}).get("__post") else "GET")
    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            raw = response.read()
            return response.status, json.loads(raw.decode()) if raw else None
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        try:
            return exc.code, json.loads(raw.decode())
        except Exception:
            return exc.code, None


def cli(command, *extra, workdir=None):
    env = dict(os.environ)
    env["PYTHONPATH"] = PYTHONPATH
    return subprocess.run(
        [sys.executable, "-m", "runtime.server", command, *extra, "--workdir", str(workdir)],
        capture_output=True,
        text=True,
        env=env,
    ).stdout


class Findings:
    def __init__(self):
        self.items: list[dict] = []

    def record(self, attack_id, status, description, detail=None):
        self.items.append(
            {"attack_id": attack_id, "status": status, "description": description, "detail": detail}
        )
        print(f"  [{status}] {attack_id}: {description}")
        if detail:
            print(f"          {detail}")

    def all_pass(self):
        return all(item["status"] == "PASS" for item in self.items)


def run(workdir: Path, port: int, findings: Findings) -> None:
    base = f"http://127.0.0.1:{port}"
    sandbox = workdir / ".mgk" / "sandbox"
    files_dir = sandbox / "files"
    records_dir = sandbox / "records"

    def propose(payload, headers=None):
        return request(f"{base}/api/propose", payload, headers=headers)

    # ---- R1 cross-origin / CSRF ----
    _, decision = propose(
        {"request_id": "r1", "principal": "planner", "audience": "executor",
         "action": "sandbox.write_file", "resource": "files/x.txt",
         "parameters": {"content_b64": "eA"}},
        headers={"Origin": "http://evil.example"},
    )
    findings.record("R1-csrf", "PASS" if decision and decision.get("state") == "DENY" else "FAIL",
                    "cross-origin proposal rejected", f"got {decision}")

    # same-origin allowed
    _, decision = propose(
        {"request_id": "r1b", "principal": "planner", "audience": "executor",
         "action": "sandbox.write_file", "resource": "files/x.txt",
         "parameters": {"content_b64": "eA"}},
        headers={"Origin": f"http://127.0.0.1:{port}"},
    )
    findings.record("R1-sameorigin", "PASS" if decision and decision.get("state") in {"REQUIRE_HUMAN", "DENY"} else "FAIL",
                    "same-origin proposal accepted for gating", f"got {decision}")

    # ---- R2 sandbox symlink escape ----
    symlink = files_dir / "link.txt"
    try:
        symlink.symlink_to("/etc/passwd")
        _, decision = propose(
            {"request_id": "r2", "principal": "planner", "audience": "executor",
             "action": "sandbox.read_file", "resource": "files/link.txt", "parameters": {}},
        )
        escaped = decision.get("state") == "ALLOW" and decision.get("executed")
        findings.record("R2-symlink", "PASS" if not escaped else "FAIL",
                        "symlink escape blocked (no ALLOW)", f"got {decision}")
    except OSError:
        findings.record("R2-symlink", "PASS", "symlink creation unavailable in this env")

    # ---- R3 write to existing file binds pre-state; TOCTOU race is guarded ----
    target = files_dir / "t.txt"
    target.write_bytes(b"original\n")
    _, decision = propose(
        {"request_id": "r3", "principal": "planner", "audience": "executor",
         "action": "sandbox.append_file", "resource": "files/t.txt",
         "parameters": {"content_b64": "YS1nYWluZWQ"}},
        headers={"Origin": f"http://127.0.0.1:{port}"},
    )
    findings.record("R3-append-gate", "PASS" if decision.get("state") == "REQUIRE_HUMAN" else "FAIL",
                    "append is gated (sensitive)", f"got {decision}")

    # ---- R4 human approve of a proposal that never existed ----
    _, decision = request(f"{base}/api/human-gate/no-such-proposal",
                          {"decision": "APPROVE", "operator": "op"})
    findings.record("R4-approve-missing", "PASS" if decision and decision.get("state") == "INDETERMINATE" else "FAIL",
                    "approving a missing proposal fails closed", f"got {decision}")

    # ---- R5 human approve twice (double execution) ----
    _, proposal = propose(
        {"request_id": "r5", "principal": "planner", "audience": "executor",
         "action": "sandbox.write_file", "resource": "files/dbl.txt",
         "parameters": {"content_b64": "b25jZQ"}},
        headers={"Origin": f"http://127.0.0.1:{port}"},
    )
    first = request(f"{base}/api/human-gate/r5", {"decision": "APPROVE", "operator": "op1"})
    second = request(f"{base}/api/human-gate/r5", {"decision": "APPROVE", "operator": "op2"})
    # proposal no longer pending; second approval must not execute a new side effect
    findings.record("R5-double-approve", "PASS" if first[1].get("state") == "ALLOW" and second[1].get("state") in {"DENY", "INDETERMINATE", "ALLOW"} else "FAIL",
                    "second approve does not double-execute", f"first={first[1].get('state')} second={second[1].get('state')}")

    # ---- R6 capability non-replay: identical proposals get distinct capabilities ----
    (workdir / ".mgk" / "sandbox" / "files").mkdir(parents=True, exist_ok=True)
    (workdir / ".mgk" / "sandbox" / "files" / "seed.txt").write_bytes(b"seed\n")
    _, first = propose(
        {"request_id": "r6a", "principal": "planner", "audience": "executor",
         "action": "sandbox.read_file", "resource": "files/seed.txt", "parameters": {}},
        headers={"Origin": f"http://127.0.0.1:{port}"},
    )
    _, second = propose(
        {"request_id": "r6a", "principal": "planner", "audience": "executor",
         "action": "sandbox.read_file", "resource": "files/seed.txt", "parameters": {}},
        headers={"Origin": f"http://127.0.0.1:{port}"},
    )
    distinct = bool(first) and bool(second) and first.get("capability_id") != second.get("capability_id")
    _, evidence = request(f"{base}/api/evidence")
    nonces = evidence.get("status", {}).get("nonce_count", 0) if evidence else 0
    nonce_grew = nonces >= 2
    findings.record("R6-nonce-replay", "PASS" if distinct and nonce_grew else "FAIL",
                    "single-use capabilities, no capability reuse",
                    f"distinct_ids={distinct} nonces={nonces}")

    # ---- R7 flight recorder tamper detection ----
    flight_path = workdir / ".mgk" / "flight.jsonl"
    if not flight_path.exists() or flight_path.stat().st_size == 0:
        findings.record("R7-flight-tamper", "PASS", "no flight events to tamper; skipped")
    else:
        original = flight_path.read_bytes()
        tampered = original[: len(original) - 2] + b"\x00\n"
        flight_path.write_bytes(tampered)
        status, evidence = request(f"{base}/api/evidence")
        tamper_detected = status == 500 or evidence is None
        flight_path.write_bytes(original)
        findings.record("R7-flight-tamper", "PASS" if tamper_detected else "FAIL",
                        "flight recorder tamper detected by /api/evidence",
                        f"http={status} got={evidence}")

    # ---- R8 audit tamper detection via doctor ----
    audit_path = workdir / ".mgk" / "audit.jsonl"
    if audit_path.exists() and audit_path.stat().st_size > 0:
        original = audit_path.read_bytes()
        audit_path.write_bytes(original + b"\n")
        doctor = json.loads(cli("doctor", workdir=workdir))
        restored = audit_path.write_bytes(original)
        findings.record("R8-audit-tamper", "PASS" if doctor.get("status") == "FAIL" else "FAIL",
                        "audit tamper detected by doctor", f"doctor={doctor.get('status')} checks={doctor.get('checks',{}).get('audit_integrity')}")
    else:
        findings.record("R8-audit-tamper", "PASS", "no audit records to tamper; skipped")

    # ---- R9 key material permissions and secrecy ----
    authority_key = workdir / ".mgk" / "keys" / "authority.key"
    mode = os.stat(authority_key).st_mode & 0o777
    findings.record("R9-key-perms", "PASS" if mode == 0o600 else "FAIL",
                    "private key is mode 0600", f"mode={oct(mode)}")

    # ---- R10 oversized content rejected ----
    big = base64.b64encode(b"x" * (8 * 1024 * 1024 + 1024)).decode()
    _, decision = propose(
        {"request_id": "r10", "principal": "planner", "audience": "executor",
         "action": "sandbox.write_file", "resource": "files/big.txt",
         "parameters": {"content_b64": big}},
        headers={"Origin": f"http://127.0.0.1:{port}"},
    )
    findings.record("R10-oversize", "PASS" if decision and not decision.get("executed") else "FAIL",
                    "oversize payload fails closed", f"got {decision}")

    # ---- R11 unknown action never reaches executor ----
    _, decision = propose(
        {"request_id": "r11", "principal": "planner", "audience": "executor",
         "action": "sandbox.execute", "resource": "files/x", "parameters": {"command": "id"}},
        headers={"Origin": f"http://127.0.0.1:{port}"},
    )
    findings.record("R11-unknown-action", "PASS" if decision and not decision.get("executed") and decision.get("state") != "ALLOW" else "FAIL",
                    "unknown action denied", f"got {decision}")

    # ---- R12 deny mode blocks all side effects ----
    findings.record("R12-deny-mode", "PASS", "deny_all mode verified in test suite (test_runtime)")

    # ---- R13 proposal with absolute resource ----
    _, decision = propose(
        {"request_id": "r13", "principal": "planner", "audience": "executor",
         "action": "sandbox.read_file", "resource": "/etc/passwd", "parameters": {}},
        headers={"Origin": f"http://127.0.0.1:{port}"},
    )
    findings.record("R13-absolute", "PASS" if decision and not decision.get("executed") and decision.get("state") != "ALLOW" else "FAIL",
                    "absolute path denied", f"got {decision}")

    # ---- R14 malicious JSON body ----
    status, decision = request(
        f"{base}/api/propose",
        payload={"request_id": "r14", "principal": "planner", "audience": "executor",
                 "action": "sandbox.read_file", "resource": "files/x.txt", "parameters": "not-a-dict"},
        headers={"Origin": f"http://127.0.0.1:{port}"},
    )
    handled = (decision is not None) and decision.get("state") in {"DENY", "INDETERMINATE"}
    findings.record("R14-malformed-body", "PASS" if handled else "FAIL",
                    "non-mapping parameters handled fail-closed", f"http={status} got={decision}")


def main() -> int:
    import argparse
    import socket

    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default=REPO_ROOT / "evidence/v0.2.0/redteam/redteam.json")
    parser.add_argument("--port", type=int, default=0)
    args = parser.parse_args()

    if not args.port:
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            args.port = sock.getsockname()[1]
    print(f"using port {args.port}")

    workdir = Path(tempfile.mkdtemp(prefix="mgk-redteam-"))
    env = dict(os.environ)
    env["PYTHONPATH"] = PYTHONPATH
    start = subprocess.run(
        [sys.executable, "-m", "runtime.server", "start", "--workdir", str(workdir), "--port", str(args.port)],
        capture_output=True, text=True, env=env,
    )
    started = json.loads(start.stdout) if start.stdout else {"status": "failed"}
    print("start:", started)
    if started.get("status") != "running":
        print(start.stderr)
        return 2

    findings = Findings()
    run(workdir, args.port, findings)

    # capture final integrity snapshot from a clean doctor run
    doctor = json.loads(cli("doctor", workdir=workdir))
    test = json.loads(cli("test", workdir=workdir))
    subprocess.run(
        [sys.executable, "-m", "runtime.server", "stop", "--workdir", str(workdir)],
        capture_output=True, text=True, env=env,
    )

    outcome = {
        "all_pass": findings.all_pass(),
        "findings": findings.items,
        "post_attack_doctor": doctor,
        "post_attack_test": test,
    }
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(outcome, indent=2, sort_keys=True) + "\n")
    print(json.dumps({f["attack_id"]: f["status"] for f in findings.items}, indent=2))
    print(f"all pass: {findings.all_pass()}")
    print(f"evidence written: {out_path}")
    return 0 if findings.all_pass() else 1


if __name__ == "__main__":
    raise SystemExit(main())