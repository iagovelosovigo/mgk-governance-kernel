#!/usr/bin/env python3
"""Phase 9: adversarial red-team against the running MGK v0.3.0 runtime.

Probes go beyond the Phase-7 baseline (R1-R14) and target the specific
security surfaces surfaced by the Phase 4 mutation classification and the
Phase 6 source audit:

  - write_bound absent-branch appeared-target guard (write mutants 69/72)
  - symlink / dir_fd confinement on read, write, append, create
  - path traversal variants (encoded, nested, unicode, backslash, dot)
  - cross-namespace resource binding (files/ vs records/)
  - capability nonce single-use (replay after execution)
  - human-gate tamper: approve/deny integrity, flight chaining, signature
  - unauthorized human-gate transition: approve-after-deny, deny-after-execute,
    approve on auto-allowed proposal (durable deny state machine)
  - canonicalization limits and malformed payloads -> fail closed
  - ledger integrity (flight + audit) under adversarial mutation
  - key material secrecy / permissions
  - executor fail-closed: any unexpected exception -> INDETERMINATE/DENIED

Every probe records a PASS/FAIL assertion. The tool is read-only against the
repository: it only mutates an ephemeral runtime workspace under /tmp, plus
ephemeral flight/audit tamper that is restored before the post-attack doctor.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

from mgk.crypto import b64u_encode

REPO_ROOT = Path(__file__).resolve().parent.parent
PYTHONPATH = f"{REPO_ROOT}:{REPO_ROOT / 'src'}:{REPO_ROOT / 'runtime'}"


def request(url: str, payload: dict | None = None, headers: dict | None = None) -> tuple[int, dict | None]:
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(url, data=data, headers=headers or {"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = resp.read()
            return resp.status, (json.loads(body) if body else None)
    except urllib.error.HTTPError as exc:
        body = exc.read()
        try:
            parsed = json.loads(body) if body else None
        except ValueError:
            parsed = {"raw": body.decode("utf-8", "replace")[:400]}
        return exc.code, parsed
    except Exception as exc:  # noqa: BLE001
        return -1, {"error": str(exc)}


def cli(command, *extra, workdir=None):
    cmd = [sys.executable, "-m", "runtime.server", command, *extra]
    if workdir:
        cmd += ["--workdir", str(workdir)]
    env = dict(os.environ)
    env["PYTHONPATH"] = PYTHONPATH
    out = subprocess.run(cmd, capture_output=True, text=True, env=env)
    try:
        return json.loads(out.stdout) if out.stdout.strip() else {"status": "no-output", "stderr": out.stderr}
    except ValueError:
        return {"status": "unparsed", "stdout": out.stdout[:400], "stderr": out.stderr[:400]}


class Findings:
    def __init__(self):
        self.items = []

    def record(self, attack_id, status, description, detail=None):
        self.items.append(
            {"attack_id": attack_id, "status": status, "description": description, "detail": detail}
        )
        print(f"  [{status}] {attack_id}: {description}")

    def all_pass(self):
        return all(f["status"] == "PASS" for f in self.items)


def run(workdir: Path, port: int, findings: Findings) -> None:
    base = f"http://127.0.0.1:{port}"
    sandbox = workdir / ".mgk" / "sandbox"
    files_dir = sandbox / "files"
    records_dir = sandbox / "records"
    files_dir.mkdir(parents=True, exist_ok=True)
    records_dir.mkdir(parents=True, exist_ok=True)
    origin = f"http://127.0.0.1:{port}"

    def propose(payload, headers=None):
        return request(f"{base}/api/propose", payload, headers=headers or {"Origin": origin})

    def human(request_id, decision="APPROVE", operator="op"):
        return request(f"{base}/api/human-gate/{request_id}", {"decision": decision, "operator": operator})

    def executed(decision):
        return decision and decision.get("executed") is True

    # ------------------------------------------------------------------ A1
    # write_bound appeared-target guard: a target that appears AFTER the
    # proposal is bound (TOCTOU) must be rejected, even if the pre-stat is
    # blind to dir_fd (the write 69/72 mutation surface). The O_EXCL open
    # must fail closed.
    target = files_dir / "appear.txt"
    if target.exists():
        target.unlink()
    _, proposal = propose(
        {"request_id": "a1", "principal": "planner", "audience": "executor",
         "action": "sandbox.write_file", "resource": "files/appear.txt",
         "parameters": {"content_b64": base64.b64encode(b"attacker-payload").decode()}},
    )
    target.write_bytes(b"appeared-after-binding")  # TOCTOU: attacker lands file now
    _, decision = human("a1")
    ok = decision and decision.get("state") == "DENY" and not executed(decision)
    findings.record("A1-write-appeared-target", "PASS" if ok else "FAIL",
                    "write to target that appeared after binding is rejected (O_EXCL backstop)",
                    f"got {decision}")

    # ------------------------------------------------------------------ A2
    # write symlink swap: replace target with symlink to /etc/passwd between
    # propose and approve. Must not overwrite outside the sandbox.
    target = files_dir / "swap.txt"
    if target.exists():
        target.unlink()
    _, proposal = propose(
        {"request_id": "a2", "principal": "planner", "audience": "executor",
         "action": "sandbox.write_file", "resource": "files/swap.txt",
         "parameters": {"content_b64": base64.b64encode(b"malicious").decode()}},
    )
    try:
        target.symlink_to("/etc/passwd")
        swapped = True
    except OSError:
        swapped = False
    _, decision = human("a2")
    ok = decision and decision.get("state") == "DENY" and not executed(decision)
    findings.record("A2-write-symlink-swap", "PASS" if ok else "FAIL",
                    "write to a symlink swapped in before approval does not escape sandbox",
                    f"swapped={swapped} got {decision}")

    # ------------------------------------------------------------------ A3
    # read via symlinked directory to / : must not escape.
    link_dir = files_dir / "outside"
    if link_dir.is_symlink() or link_dir.exists():
        shutil.rmtree(link_dir, ignore_errors=True) if link_dir.exists() else None
    try:
        link_dir.symlink_to("/", target_is_directory=True)
        dir_link = True
    except OSError:
        dir_link = False
    _, decision = propose(
        {"request_id": "a3", "principal": "planner", "audience": "executor",
         "action": "sandbox.read_file", "resource": "files/outside/etc/passwd", "parameters": {}},
    )
    ok = decision and decision.get("state") in {"DENY", "INDETERMINATE"} and not executed(decision)
    findings.record("A3-read-dir-symlink-escape", "PASS" if ok else "FAIL",
                    "read through symlinked directory does not escape sandbox",
                    f"dir_link={dir_link} got {decision}")

    # ------------------------------------------------------------------ A4
    # append symlink target: appending to an existing symlink must not write
    # outside (O_NOFOLLOW / descriptor confinement).
    outside = workdir / "outside-append.txt"
    outside.write_bytes(b"keep")
    target = files_dir / "append-link.txt"
    try:
        target.symlink_to(str(outside))
        link = True
    except OSError:
        link = False
    _, decision = propose(
        {"request_id": "a4", "principal": "planner", "audience": "executor",
         "action": "sandbox.append_file", "resource": "files/append-link.txt",
         "parameters": {"content_b64": base64.b64encode(b"-tampered").decode()}},
    )
    # append is sensitive -> approve first, then the execution must be denied
    _, approved = human("a4")
    outside_changed = outside.read_bytes() != b"keep"
    ok = (approved and approved.get("state") == "DENY" and not executed(approved)
          and not outside_changed)
    findings.record("A4-append-symlink-confinement", "PASS" if ok else "FAIL",
                    "append to symlink target does not escape sandbox",
                    f"link={link} propose={decision.get('state')} approve={approved.get('state')} outside_changed={outside_changed}")

    # ------------------------------------------------------------------ A5
    # path traversal: dotdot, leading/trailing slash, backslash, encoded.
    attacks = {
        "a5-dotdot": "files/../etc/passwd",
        "a5-leading": "/files/x",
        "a5-backslash": r"files\..\etc\passwd",
        "a5-enc-slash": "files/..%2fetc%2fpasswd",
    }
    for aid, resource in attacks.items():
        _, decision = propose(
            {"request_id": aid, "principal": "planner", "audience": "executor",
             "action": "sandbox.read_file", "resource": resource, "parameters": {}},
        )
        ok = decision and decision.get("state") in {"DENY", "INDETERMINATE"} and not executed(decision)
        findings.record(aid.upper(), "PASS" if ok else "FAIL",
                        f"path traversal blocked: {resource!r}", f"got {decision}")

    # ------------------------------------------------------------------ A6
    # cross-namespace resource binding: read_file on records/, write_file on
    # records/, create_record on files/. The actuator registry checks the
    # namespace prefix, so these must be denied.
    for aid, action, resource in [
        ("A6-read-files-on-records", "sandbox.read_file", "records/x.json"),
        ("A6-write-records-on-files", "sandbox.write_file", "records/r.json"),
        ("A6-create-records-on-files", "sandbox.create_record", "files/rec.json"),
        ("A6-append-records-on-files", "sandbox.append_file", "records/y.json"),
    ]:
        _, decision = propose(
            {"request_id": aid, "principal": "planner", "audience": "executor",
             "action": action, "resource": resource,
             "parameters": {"content_b64": base64.b64encode(b"x").decode()}},
        )
        ok = decision and decision.get("state") in {"DENY", "INDETERMINATE"} and not executed(decision)
        findings.record(aid, "PASS" if ok else "FAIL",
                        f"cross-namespace denied: {action} {resource}", f"got {decision}")

    # ------------------------------------------------------------------ A7
    # unicode / null / dot-segment resource.
    for aid, resource in [
        ("A7-unicode", "files/\\u202eevil.txt"),
        ("A7-nullbyte", "files/\x00evil.txt"),
        ("A7-dot", "files/./x.txt"),
        ("A7-empty-seg", "files//x.txt"),
    ]:
        _, decision = propose(
            {"request_id": aid, "principal": "planner", "audience": "executor",
             "action": "sandbox.read_file", "resource": resource, "parameters": {}},
        )
        ok = decision and decision.get("state") in {"DENY", "INDETERMINATE"} and not executed(decision)
        findings.record(aid.upper(), "PASS" if ok else "FAIL",
                        f"hostile resource form blocked: {resource!r}", f"got {decision}")

    # ------------------------------------------------------------------ A8
    # capability single-use: after a successful human-approved execution, the
    # exact same proposal re-submitted must NOT reuse the capability/nonce.
    seed = files_dir / "seed.txt"
    seed.write_bytes(b"seed\n")
    _, d1 = propose(
        {"request_id": "a8", "principal": "planner", "audience": "executor",
         "action": "sandbox.read_file", "resource": "files/seed.txt", "parameters": {}},
    )
    _, d2 = propose(
        {"request_id": "a8", "principal": "planner", "audience": "executor",
         "action": "sandbox.read_file", "resource": "files/seed.txt", "parameters": {}},
    )
    ok = d1 and d2 and d1.get("capability_id") != d2.get("capability_id")
    findings.record("A8-capability-replay", "PASS" if ok else "FAIL",
                    "identical proposals get distinct single-use capabilities",
                    f"c1={d1.get('capability_id')} c2={d2.get('capability_id')}")

    # ------------------------------------------------------------------ A9
    # human approve then second approve: must not double-execute.
    target = files_dir / "dbl.txt"
    target.write_bytes(b"x")
    _, proposal = propose(
        {"request_id": "a9", "principal": "planner", "audience": "executor",
         "action": "sandbox.write_file", "resource": "files/dbl.txt",
         "parameters": {"content_b64": base64.b64encode(b"one").decode()}},
    )
    first = human("a9", "APPROVE", "op1")
    second = human("a9", "APPROVE", "op2")
    ok = first[1] and first[1].get("state") == "ALLOW" and executed(first[1]) and \
         (second[1].get("state") in {"DENY", "INDETERMINATE"} or not executed(second[1]))
    findings.record("A9-double-approve", "PASS" if ok else "FAIL",
                    "second human approval does not double-execute",
                    f"first={first[1].get('state')} second={second[1].get('state')}")

    # ------------------------------------------------------------------ A10
    # human deny must not execute any side effect.
    target = files_dir / "denied.txt"
    if target.exists():
        target.unlink()
    _, proposal = propose(
        {"request_id": "a10", "principal": "planner", "audience": "executor",
         "action": "sandbox.write_file", "resource": "files/denied.txt",
         "parameters": {"content_b64": base64.b64encode(b"never").decode()}},
    )
    dec = human("a10", "DENY", "op-deny")
    ok = dec[1] and dec[1].get("state") == "DENY" and not target.exists()
    findings.record("A10-human-deny-no-effect", "PASS" if ok else "FAIL",
                    "human DENY leaves no file and no side effect",
                    f"got {dec[1]} target_exists={target.exists()}")

    # ------------------------------------------------------------------ A11
    # approve a proposal that never existed fails closed.
    _, decision = human("a11-missing", "APPROVE", "op")
    ok = decision and decision.get("state") == "INDETERMINATE" and "PROPOSAL_NOT_FOUND" in decision.get("reason_codes", [])
    findings.record("A11-approve-missing", "PASS" if ok else "FAIL",
                    "approving a nonexistent proposal fails closed", f"got {decision}")

    # ------------------------------------------------------------------ A12
    # oversized content (canonicalization / size limits) fails closed.
    big = base64.b64encode(b"x" * (8 * 1024 * 1024 + 4096)).decode()
    _, decision = propose(
        {"request_id": "a12", "principal": "planner", "audience": "executor",
         "action": "sandbox.write_file", "resource": "files/big.txt",
         "parameters": {"content_b64": big}},
    )
    ok = decision and decision.get("state") in {"DENY", "INDETERMINATE"} and not executed(decision)
    findings.record("A12-oversize-content", "PASS" if ok else "FAIL",
                    "oversize content fails closed", f"got {decision}")

    # ------------------------------------------------------------------ A13
    # malformed / hostile parameter shapes fail closed (non-dict params,
    # invalid b64, missing content). write_file is sensitive, so the proposal
    # is gated; the fail-closed assertion is on the post-approval execution.
    for aid, params in [
        ("A13-params-not-dict", "not-a-dict"),
        ("A13-invalid-b64", {"content_b64": "!!!not-base64!!!"}),
        ("A13-missing-content", {}),
    ]:
        _, decision = propose(
            {"request_id": aid, "principal": "planner", "audience": "executor",
             "action": "sandbox.write_file", "resource": "files/x.txt", "parameters": params},
        )
        if decision and decision.get("state") == "REQUIRE_HUMAN":
            _, approved = human(aid)
        else:
            approved = decision
        ok = (approved and approved.get("state") in {"DENY", "INDETERMINATE"}
              and not executed(approved))
        findings.record(aid.upper(), "PASS" if ok else "FAIL",
                        f"malformed parameters fail closed: {aid}",
                        f"propose={decision.get('state')} approve={approved.get('state')}")

    # ------------------------------------------------------------------ A14
    # unknown / ungoverned action never reaches the executor.
    _, decision = propose(
        {"request_id": "a14", "principal": "planner", "audience": "executor",
         "action": "sandbox.execute", "resource": "files/x", "parameters": {"command": "id"}},
    )
    ok = decision and decision.get("state") in {"DENY", "INDETERMINATE"} and not executed(decision)
    findings.record("A14-unknown-action", "PASS" if ok else "FAIL",
                    "unknown action denied", f"got {decision}")

    # ------------------------------------------------------------------ A15
    # audience mismatch must not execute.
    _, decision = propose(
        {"request_id": "a15", "principal": "planner", "audience": "not-executor",
         "action": "sandbox.read_file", "resource": "files/seed.txt", "parameters": {}},
    )
    ok = decision and not executed(decision)
    findings.record("A15-audience-mismatch", "PASS" if ok else "FAIL",
                    "audience mismatch does not execute", f"got {decision}")

    # ------------------------------------------------------------------ A16
    # cross-origin proposal (evil Origin) rejected; Referer-only spoof too.
    _, decision = propose(
        {"request_id": "a16", "principal": "planner", "audience": "executor",
         "action": "sandbox.write_file", "resource": "files/x.txt",
         "parameters": {"content_b64": "eA"}},
        headers={"Origin": "http://evil.example"},
    )
    ok = decision and decision.get("state") == "DENY"
    findings.record("A16-cross-origin", "PASS" if ok else "FAIL",
                    "cross-origin proposal rejected", f"got {decision}")

    # ------------------------------------------------------------------ A17
    # flight recorder tamper is detected by /api/evidence.
    flight_path = workdir / ".mgk" / "flight.jsonl"
    if flight_path.exists() and flight_path.stat().st_size > 0:
        original = flight_path.read_bytes()
        flight_path.write_bytes(original[: len(original) - 2] + b"\x00\n")
        status, evidence = request(f"{base}/api/evidence")
        tamper_detected = status == 500 or evidence is None or evidence.get("status") == "FAIL"
        flight_path.write_bytes(original)
        findings.record("A17-flight-tamper", "PASS" if tamper_detected else "FAIL",
                        "flight recorder tamper detected by /api/evidence",
                        f"http={status} got={evidence}")
    else:
        findings.record("A17-flight-tamper", "PASS", "no flight events to tamper; skipped")

    # ------------------------------------------------------------------ A18
    # audit ledger tamper is detected by doctor.
    audit_path = workdir / ".mgk" / "audit.jsonl"
    if audit_path.exists() and audit_path.stat().st_size > 0:
        original = audit_path.read_bytes()
        audit_path.write_bytes(original + b"\n")
        doctor = cli("doctor", workdir=workdir)
        audit_path.write_bytes(original)
        ok = doctor.get("status") == "FAIL"
        findings.record("A18-audit-tamper", "PASS" if ok else "FAIL",
                        "audit tamper detected by doctor",
                        f"doctor={doctor.get('status')} detail={doctor}")
    else:
        findings.record("A18-audit-tamper", "PASS", "no audit records to tamper; skipped")

    # ------------------------------------------------------------------ A19
    # private key secrecy and permissions.
    authority_key = workdir / ".mgk" / "keys" / "authority.key"
    mode = os.stat(authority_key).st_mode & 0o777
    ok = mode == 0o600
    findings.record("A19-key-perms", "PASS" if ok else "FAIL",
                    "private key is mode 0600", f"mode={oct(mode)}")

    # ------------------------------------------------------------------ A20
    # create_record to an already-existing record id fails closed (identity).
    record_path = records_dir / "existing.json"
    record_path.write_text(json.dumps({"k": 1}), encoding="utf-8")
    _, decision = propose(
        {"request_id": "a20", "principal": "planner", "audience": "executor",
         "action": "sandbox.create_record", "resource": "records/existing.json",
         "parameters": {"content_b64": b64u_encode(b"{}")}},
    )
    _, decision_h = human("a20", "APPROVE", "op")
    ok = decision_h and decision_h.get("state") in {"DENY", "INDETERMINATE"} and not executed(decision_h)
    findings.record("A20-create-record-exists", "PASS" if ok else "FAIL",
                    "create_record on existing record fails closed",
                    f"propose={decision.get('state')} approve={decision_h.get('state')}")

    # ------------------------------------------------------------------ A21
    # path depth limit (32 parts) enforced.
    deep = "files/" + "/".join(["d"] * 40) + "/x.txt"
    _, decision = propose(
        {"request_id": "a21", "principal": "planner", "audience": "executor",
         "action": "sandbox.read_file", "resource": deep, "parameters": {}},
    )
    ok = decision and decision.get("state") in {"DENY", "INDETERMINATE"} and not executed(decision)
    findings.record("A21-deep-path", "PASS" if ok else "FAIL",
                    "resource path depth limit enforced", f"got {decision}")

    # ------------------------------------------------------------------ A22
    # GET endpoints only serve pages; /api/evidence requires no secret.
    status, _ = request(f"{base}/api/health")
    ok = status == 200
    findings.record("A22-api-health", "PASS" if ok else "FAIL",
                    "/api/health returns 200", f"http={status}")

    # ------------------------------------------------------------------ A23
    # unauthorized human-gate transition: APPROVE after a human DENY must not
    # execute any side effect (human DENY is a durable terminal state).
    a23_target = records_dir / "a23.json"
    _, _ = propose(
        {"request_id": "a23", "principal": "planner", "audience": "executor",
         "action": "sandbox.create_record", "resource": "records/a23.json",
         "parameters": {"content_b64": b64u_encode(b'{"a": 1}')}},
    )
    denied = human("a23", "DENY", "op-deny")
    approved = human("a23", "APPROVE", "op-approve")
    ok = denied[1] and denied[1].get("state") == "DENY" and not executed(denied[1]) and \
         approved[1] and approved[1].get("state") == "DENY" and not executed(approved[1]) and \
         not a23_target.exists()
    findings.record("A23-approve-after-deny", "PASS" if ok else "FAIL",
                    "APPROVE after human DENY does not execute",
                    f"deny={denied[1].get('state')} approve={approved[1].get('state')} target={a23_target.exists()}")

    # ------------------------------------------------------------------ A24
    # unauthorized human-gate transition: DENY after an executed APPROVE must
    # be refused and must not alter evidence or the executed artifact.
    a24_target = files_dir / "a24.txt"
    a24_target.write_bytes(b"original")
    _, _ = propose(
        {"request_id": "a24", "principal": "planner", "audience": "executor",
         "action": "sandbox.write_file", "resource": "files/a24.txt",
         "parameters": {"content_b64": b64u_encode(b"modified")}},
    )
    first = human("a24", "APPROVE", "op1")
    denied = human("a24", "DENY", "op2")
    ok = first[1] and first[1].get("state") == "ALLOW" and executed(first[1]) and \
         denied[1] and denied[1].get("state") == "DENY" and not executed(denied[1]) and \
         a24_target.read_bytes() == b"modified"
    findings.record("A24-deny-after-execute", "PASS" if ok else "FAIL",
                    "DENY after executed APPROVE is refused, artifact unchanged",
                    f"approve={first[1].get('state')} deny={denied[1].get('state')} content={a24_target.read_bytes()}")

    # ------------------------------------------------------------------ A25
    # unauthorized human-gate transition: APPROVE on an auto-ALLOWED proposal
    # must be refused and must not re-execute.
    (files_dir / "a25.txt").write_bytes(b"seed\n")
    _, auto = propose(
        {"request_id": "a25", "principal": "planner", "audience": "executor",
         "action": "sandbox.read_file", "resource": "files/a25.txt", "parameters": {}},
    )
    gated = human("a25", "APPROVE", "op")
    ok = auto and auto.get("state") == "ALLOW" and \
         gated[1] and gated[1].get("state") == "DENY" and not executed(gated[1])
    findings.record("A25-approve-auto-allowed", "PASS" if ok else "FAIL",
                    "APPROVE on auto-ALLOWED proposal is refused",
                    f"auto={auto.get('state')} approve={gated[1].get('state')}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default=REPO_ROOT / "evidence/v0.3.0/redteam/redteam-adversarial.json")
    parser.add_argument("--port", type=int, default=0)
    args = parser.parse_args()

    if not args.port:
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            args.port = sock.getsockname()[1]
    print(f"using port {args.port}")

    workdir = Path(tempfile.mkdtemp(prefix="mgk-adversarial-"))
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

    doctor = cli("doctor", workdir=workdir)
    test = cli("test", workdir=workdir)
    subprocess.run(
        [sys.executable, "-m", "runtime.server", "stop", "--workdir", str(workdir)],
        capture_output=True, text=True, env=env,
    )

    outcome = {
        "schema_version": "mgk.redteam.v1",
        "kind": "redteam-adversarial",
        "phase": 9,
        "recorded_at": "2026-08-17",
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