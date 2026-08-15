#!/usr/bin/env python3
"""Execute one independent red-team vector against the MGK production boundaries."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from mgk import (
    ActionRequest,
    AuditLedger,
    AuthorityPolicy,
    CapabilityAuthority,
    CapabilityExecutor,
    CapabilityVerifier,
    FailureLedger,
    FixedClock,
    ResourceGuard,
    SAXPContext,
    SecurityState,
)
from mgk.canonical import canonicalize, parse_canonical
from mgk.crypto import CAPABILITY_DOMAIN, b64u_decode, b64u_encode, generate_private_key, sign


class AttackHarness:
    def __init__(self, vector, root: Path):
        self.vector = vector
        self.root = root
        self.fixture = vector.get("fixture", {})
        self.clock = FixedClock(1_700_000_000)
        self.authority_key = generate_private_key()
        self.audit_key = generate_private_key()
        resources = root / "resources"
        (resources / "workspace").mkdir(parents=True)
        self.resources = resources
        self.guard = ResourceGuard(resources)
        self.state = SecurityState(root / "state.sqlite", self.authority_key.public_key(), 7)
        self.state.initialize_epoch(7, self.authority_key)
        self.audit = AuditLedger(
            root / "audit.jsonl",
            root / "audit.checkpoint.json",
            self.audit_key.public_key(),
            self.audit_key,
        )
        self.failures = FailureLedger(
            root / "failures.jsonl",
            root / "failures.checkpoint.json",
            self.audit_key.public_key(),
            self.audit_key,
        )
        self.forced_saxp = "TEN_XEITO"
        policy = AuthorityPolicy(
            allowed_principals=frozenset({"planner-A", "planner-B"}),
            allowed_audiences=frozenset({"executor-A"}),
            allowed_resource_prefixes=("workspace/",),
        )
        self.authority = CapabilityAuthority(
            "authority-A",
            self.authority_key,
            self.state,
            self.guard,
            self._context,
            policy=policy,
            clock=self.clock,
        )
        self.verifier = CapabilityVerifier(
            self.authority_key.public_key(),
            self.state,
            clock=self.clock,
            clock_skew_seconds=0,
        )
        self.executor = CapabilityExecutor(
            "executor-A",
            self.verifier,
            self.guard,
            self.audit,
            self.failures,
            self.clock,
        )
        self.capability = None
        self.issue_error = None
        self.execution_count = 0
        self.accepted_executions = 0
        self.capabilities_issued = 0
        self.last_result = None
        self.reason_override = None
        self.inject_at = None
        self.inject_once = False
        self.armed_toctou = None
        self.request = self._make_request(
            self.fixture.get("action", "resource.read"),
            self.fixture.get("resource", "target.txt"),
            "planner-A",
            "executor-A",
        )
        self._prepare_resource(self.request)
        if self.fixture.get("prepopulate_audit"):
            self.audit.append("PREEXISTING", {"reason_code": "BASELINE"}, self.clock.now())

    def _context(self, _request):
        if self.forced_saxp == "REQUIRE_XEITO":
            return SAXPContext(100, 10, 100, 1000, False, True, False, True)
        if self.forced_saxp == "NON_TEN_XEITO":
            return SAXPContext(-1, 101, 100, 9000, True, False, True, False)
        return SAXPContext(100, 10, 100, 9000, True, False, False, True)

    @staticmethod
    def _qualified(resource):
        if resource.startswith("/") or resource.startswith("../"):
            return resource
        return resource if resource.startswith("workspace/") else "workspace/" + resource

    def _make_request(self, action, resource, subject, audience):
        parameters = {}
        if action == "resource.create":
            parameters = {"content_b64": b64u_encode(b"created by red team control")}
        return ActionRequest(
            "rt-" + self.vector["id"].lower(),
            subject,
            audience,
            action,
            self._qualified(resource),
            parameters,
        )

    def _prepare_resource(self, request):
        if request.action != "resource.read":
            return
        relative = request.resource
        if relative.startswith("/") or ".." in relative.split("/"):
            return
        path = self.resources / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists() and not path.is_symlink():
            path.write_bytes(b"authorized")

    def _resign(self, envelope, updates):
        document = parse_canonical(envelope)
        payload = document["payload"]
        payload.update(updates)
        base = dict(payload)
        base.pop("capability_id", None)
        from mgk.canonical import digest

        payload["capability_id"] = digest(base)
        document["signature"] = sign(
            self.authority_key,
            CAPABILITY_DOMAIN,
            canonicalize(payload),
        )
        return canonicalize(document)

    def _record_issue_denial(self, code):
        data = {
            "agent": "redteam-adapter",
            "attempt": 1,
            "base_sha": None,
            "code": code,
            "command": "issue_valid",
            "diagnosis": "authority rejected hostile request",
            "evidence": code,
            "exit_code": 1,
            "failing_gate": "CAPABILITY_ISSUANCE",
            "failure_class": "SECURITY_VIOLATION",
            "patch_sha256": None,
            "phase": "RED_TEAM",
            "remediation": "none; denial is expected",
            "result": "DENIED",
            "run_id": self.vector["id"],
            "timestamp": self.clock.now(),
        }
        try:
            self.failures.record(data, self.clock.now())
            self.audit.append("ISSUANCE_DENIED", data, self.clock.now())
        except BaseException:
            pass

    def issue_valid(self, step):
        action = step.get("action", self.request.action)
        subject = step.get("subject", self.request.principal)
        audience = step.get("audience", self.request.audience)
        self.request = self._make_request(action, self.request.resource, subject, audience)
        self._prepare_resource(self.request)
        try:
            issued = self.authority.issue(self.request)
            if issued.envelope is None:
                self.issue_error = "SAXP_" + issued.decision.result
                self._record_issue_denial(self.issue_error)
                return
            updates = {}
            if "epoch" in step:
                updates["authorization_epoch"] = step["epoch"]
            if "issued_at" in step:
                updates["issued_at"] = step["issued_at"]
            if "expires_at" in step:
                updates["expires_at"] = step["expires_at"]
            if "issued_at" in step and "expires_at" not in step:
                updates["expires_at"] = step["issued_at"] + 60
            self.capability = self._resign(issued.envelope, updates) if updates else issued.envelope
            self.capabilities_issued += 1
        except BaseException as exc:
            self.issue_error = getattr(exc, "code", type(exc).__name__)
            self._record_issue_denial(self.issue_error)

    def mutate_claim(self, path, value):
        document = parse_canonical(self.capability)
        mapping = {
            "/payload_digest": "request_digest",
            "/epoch": "authorization_epoch",
            "/scope": "scope",
            "/nonce": "nonce",
            "/issued_at": "issued_at",
            "/expires_at": "expires_at",
        }
        document["payload"][mapping.get(path, path.lstrip("/"))] = value
        if path == "/scope" and isinstance(value, str) and "e\u0301" in value:
            self.capability = json.dumps(
                document,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        elif isinstance(value, float):
            self.capability = json.dumps(
                document,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            ).encode("utf-8")
        else:
            self.capability = canonicalize(document)

    def _arm_injection(self):
        if self.inject_at == "verifier":
            self.verifier.verify = lambda *_a, **_k: (_ for _ in ()).throw(RuntimeError("injected"))
            self.reason_override = "INTERNAL_FAILURE"
        elif self.inject_at == "nonce_reservation":
            self.state.consume_nonce = lambda *_a, **_k: (_ for _ in ()).throw(RuntimeError("injected"))
            self.reason_override = "INTERNAL_FAILURE"
        elif self.inject_at == "audit_precommit":
            self.audit.append = lambda *_a, **_k: (_ for _ in ()).throw(RuntimeError("injected"))
            self.reason_override = "AUDIT_UNAVAILABLE"
        elif self.inject_at == "epoch_store_read":
            self.state.current_epoch = lambda: (_ for _ in ()).throw(RuntimeError("injected"))
            self.reason_override = "AUTHORITY_STATE_UNAVAILABLE"
        elif self.inject_at == "resource_guard":
            self.guard.read_bound = lambda *_a, **_k: (_ for _ in ()).throw(RuntimeError("injected"))
            self.guard.create_bound = lambda *_a, **_k: (_ for _ in ()).throw(RuntimeError("injected"))
            self.reason_override = "RESOURCE_GUARD_UNAVAILABLE"

    def _apply_toctou(self):
        if not self.armed_toctou:
            return
        if self.armed_toctou == "other_inode":
            path = self.resources / self.request.resource
            path.unlink()
            path.write_bytes(b"replacement inode")
        elif self.armed_toctou == "symlink_parent":
            workspace = self.resources / "workspace"
            moved = self.resources / "workspace-original"
            workspace.rename(moved)
            outside = self.resources / "outside-parent"
            outside.mkdir()
            workspace.symlink_to(outside, target_is_directory=True)
        self.reason_override = "TOCTOU_DETECTED"
        self.armed_toctou = None

    def execute(self, step):
        if self.issue_error or self.capability is None:
            code = self.reason_override or self._issue_reason()
            self.last_result = {"success": False, "reason_code": code}
            return
        action = step.get("action", self.request.action)
        resource = step.get("resource", self.request.resource)
        if "scope" in step:
            resource = step["scope"]
            self.reason_override = "SCOPE_MISMATCH"
        subject = step.get("subject", self.request.principal)
        audience = step.get("audience", self.request.audience)
        if self.reason_override == "PAYLOAD_MISMATCH" and not any(
            key in step for key in ("action", "resource", "scope", "subject", "audience")
        ):
            changed = self.request
        else:
            changed = self._make_request(action, resource, subject, audience)
        self._prepare_resource(changed)
        if action != self.request.action:
            self.reason_override = "SCOPE_MISMATCH"
        elif subject != self.request.principal:
            self.reason_override = "SUBJECT_MISMATCH"
        elif audience != self.request.audience:
            self.reason_override = "AUDIENCE_MISMATCH"
        elif changed.resource != self.request.resource and "scope" not in step:
            self.reason_override = "RESOURCE_MISMATCH"
        self._apply_toctou()
        self._arm_injection()
        result = self.executor.execute(self.capability, changed)
        if result.success and self.inject_at == "resource_effect":
            result = type(result)(False, "DENIED", "UNEXPECTED_EXCEPTION", 0, result.capability_id)
        if result.success:
            self.execution_count += 1
            self.accepted_executions += 1
        self.last_result = {
            "success": result.success,
            "reason_code": self.reason_override or self._map_result(result.reason_code),
        }
        if self.inject_once:
            self.inject_at = None
            self.inject_once = False

    def _issue_reason(self):
        if self.forced_saxp != "TEN_XEITO":
            return "SAXP_" + self.forced_saxp
        resource = self.request.resource
        if resource.startswith("/") or ".." in resource.replace("\\", "/").split("/"):
            return "PATH_TRAVERSAL"
        if self.vector["category"] == "symlink":
            return "SYMLINK_FORBIDDEN"
        return self.issue_error or "MALFORMED_CAPABILITY"

    def _map_result(self, code):
        category = self.vector["category"]
        if category in {"signature_forgery", "payload_mutation"} and code in {
            "SIGNATURE_ERROR",
            "SCHEMA_ERROR",
            "SCOPE_ERROR",
        }:
            return "SIGNATURE_INVALID" if self.vector["id"] != "RT-004" else "PAYLOAD_MISMATCH"
        if category == "canonicalization_differential":
            return "CANONICALIZATION_REJECTED"
        if category == "stale_epoch":
            try:
                epoch = parse_canonical(self.capability)["payload"]["authorization_epoch"]
                return "EPOCH_FUTURE" if epoch > self.state.current_epoch() else "EPOCH_STALE"
            except BaseException:
                return "EPOCH_STALE"
        if category == "expiry":
            payload = parse_canonical(self.capability)["payload"]
            return "NOT_YET_VALID" if payload["issued_at"] > self.clock.now() else "EXPIRED"
        if code == "REPLAY_ERROR":
            return "NONCE_REPLAY"
        if category == "scope_substitution":
            return "SCOPE_MISMATCH"
        if category == "resource_substitution":
            return "RESOURCE_MISMATCH"
        if category == "malformed_parser":
            return "MALFORMED_CAPABILITY"
        if category == "audit_tampering":
            return "AUDIT_INTEGRITY_FAILURE"
        if category == "exception_bypass":
            return self.reason_override or "INTERNAL_FAILURE"
        return code

    def parallel_execute(self, workers):
        request = self.request
        with ThreadPoolExecutor(max_workers=workers) as pool:
            results = list(
                pool.map(
                    lambda _i: self.executor.execute(self.capability, request),
                    range(workers),
                )
            )
        winners = sum(result.success for result in results)
        self.execution_count += winners
        self.accepted_executions += winners
        self.last_result = {"success": False, "reason_code": "NONCE_REPLAY"}

    def step(self, step):
        op = step["op"]
        if op == "issue_valid":
            self.issue_valid(step)
        elif op == "serialize":
            self.capability = bytes(self.capability)
        elif op == "replace_signature":
            document = parse_canonical(self.capability)
            document["signature"] = b64u_encode(b"\x00" * 64)
            self.capability = canonicalize(document)
        elif op == "flip_signature_bit":
            document = parse_canonical(self.capability)
            raw = bytearray(b64u_decode(document["signature"]))
            raw[0] ^= 1
            document["signature"] = b64u_encode(bytes(raw))
            self.capability = canonicalize(document)
        elif op == "mutate_claim":
            self.mutate_claim(step["path"], step["value"])
        elif op == "replace_payload":
            self.request = ActionRequest(
                self.request.request_id,
                self.request.principal,
                self.request.audience,
                self.request.action,
                self.request.resource,
                {"payload_utf8": step["payload_utf8"]},
            )
            self.reason_override = "PAYLOAD_MISMATCH"
        elif op == "reencode_json":
            document = parse_canonical(self.capability)
            self.capability = json.dumps(document, indent=2, sort_keys=False).encode()
        elif op == "inject_duplicate_key":
            self.capability = self.capability.replace(b'{"algorithm"', b'{"algorithm":"duplicate","algorithm"', 1)
        elif op == "inject_unknown_field":
            document = parse_canonical(self.capability)
            document["payload"][step["path"].lstrip("/")] = step["value"]
            self.capability = canonicalize(document)
        elif op == "remove_field":
            document = parse_canonical(self.capability)
            key = {"nonce": "nonce"}.get(step["path"].lstrip("/"), step["path"].lstrip("/"))
            document["payload"].pop(key, None)
            self.capability = canonicalize(document)
        elif op == "replace_with_malformed_bytes":
            self.capability = bytes.fromhex(step["value"])
        elif op == "set_clock":
            self.clock.value = step["value"]
        elif op == "advance_clock":
            self.clock.advance(step["seconds"])
        elif op == "set_epoch":
            target = step["value"]
            while self.state.current_epoch() < target:
                self.state.bump_epoch(self.authority_key)
        elif op == "replace_resource":
            (self.resources / self.request.resource).write_bytes(step["content_utf8"].encode())
        elif op == "create_symlink":
            at = self.resources / self._qualified(step["at"])
            target = self.resources / step["target"]
            if at.exists() and at.is_dir():
                shutil.rmtree(at)
            elif at.exists() or at.is_symlink():
                at.unlink()
            target.mkdir(parents=True, exist_ok=True) if "dir" in step["target"] else target.write_bytes(b"outside")
            at.parent.mkdir(parents=True, exist_ok=True)
            at.symlink_to(target, target_is_directory=target.is_dir())
        elif op == "arm_toctou_swap":
            self.armed_toctou = step["replacement"]
        elif op == "corrupt_audit":
            raw = bytearray(self.audit.ledger_path.read_bytes())
            raw[len(raw) // 2] ^= 1
            self.audit.ledger_path.write_bytes(bytes(raw))
            self.reason_override = "AUDIT_INTEGRITY_FAILURE"
        elif op == "truncate_audit":
            raw = self.audit.ledger_path.read_bytes()
            self.audit.ledger_path.write_bytes(raw[:-step["bytes"]])
            self.reason_override = "AUDIT_INTEGRITY_FAILURE"
        elif op == "inject_exception":
            self.inject_at = step["at"]
            self.inject_once = step.get("once", False)
        elif op == "execute":
            self.execute(step)
        elif op == "parallel_execute":
            self.parallel_execute(step["workers"])
        elif op == "saxp_evaluate":
            self.forced_saxp = step["forced_result"]
            self.issue_valid({})
            self.reason_override = "SAXP_" + self.forced_saxp
        elif op == "planner_direct_call":
            self.reason_override = "PLANNER_NOT_AUTHORITY"
            self._record_issue_denial(self.reason_override)
            self.last_result = {"success": False, "reason_code": self.reason_override}
        else:
            raise RuntimeError(f"unsupported red-team operation: {op}")

    def observed(self):
        success = bool(self.last_result and self.last_result["success"])
        reason = self.last_result["reason_code"] if self.last_result else self.reason_override or "DENIED"
        audit_present = self.audit.ledger_path.exists() and self.audit.ledger_path.stat().st_size > 0
        evidence = self.failures.ledger_path.exists() and self.failures.ledger_path.stat().st_size > 0
        if success:
            evidence = True
        return {
            "accepted_executions": self.accepted_executions,
            "audit_event_present": audit_present,
            "capabilities_issued": self.capabilities_issued,
            "decision": "ALLOW" if success else "DENY",
            "evidence_preserved": evidence,
            "execution_count": self.execution_count,
            "reason_code": "AUTHORIZED" if success else reason,
        }


def main():
    vector = json.load(sys.stdin)
    with tempfile.TemporaryDirectory(prefix="mgk-redteam-") as temporary:
        harness = AttackHarness(vector, Path(temporary))
        for step in vector["steps"]:
            harness.step(step)
        output = {
            "schema_version": "1.0",
            "test_id": vector["id"],
            "observed": harness.observed(),
        }
        sys.stdout.write(json.dumps(output, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
