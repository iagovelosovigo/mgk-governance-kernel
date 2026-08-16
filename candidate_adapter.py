"""Adapter binding the frozen independent examination to the production MGK primitives.

The adapter is test-only. It maps arbitrary examination requests onto a bound read resource;
production execution remains limited to the closed action registry in ``CapabilityExecutor``.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Mapping, Sequence

from cryptography.hazmat.primitives import serialization

from mgk import (
    ActionRequest,
    AuditLedger,
    AuthorityPolicy,
    CapabilityAuthority,
    CapabilityVerifier,
    FailureLedger,
    FixedClock,
    ResourceGuard,
    SAXPContext,
    SecurityState,
)
from mgk.canonical import canonicalize, digest, parse_canonical
from mgk.crypto import CAPABILITY_DOMAIN, b64u_decode, b64u_encode, generate_private_key, key_id, sign


class _Clock:
    def __init__(self, frozen):
        self.frozen = frozen

    def now(self):
        return self.frozen.now


class Harness:
    def __init__(self, root: Path, frozen_clock):
        self.root = root
        self.clock = _Clock(frozen_clock)
        self.authority_key = generate_private_key()
        self.audit_key = generate_private_key()
        resources = root / "resources"
        (resources / "workspace").mkdir(parents=True)
        self.guard = ResourceGuard(resources)
        self.state = SecurityState(root / "state.sqlite", self.authority_key.public_key(), 1)
        self.state.initialize_epoch(1, self.authority_key)
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
        policy = AuthorityPolicy(
            allowed_principals=frozenset({"planner"}),
            allowed_audiences=frozenset({"executor"}),
            allowed_resource_prefixes=("workspace/",),
        )
        self.authority = CapabilityAuthority(
            "exam-authority",
            self.authority_key,
            self.state,
            self.guard,
            lambda _request: self._safe_context(),
            policy=policy,
            clock=self.clock,
        )
        self.verifier = CapabilityVerifier(
            self.authority_key.public_key(),
            self.state,
            clock=self.clock,
        )

    @staticmethod
    def _safe_context():
        return SAXPContext(100, 10, 100, 9000, True, False, False, True)

    @staticmethod
    def canonicalize(value):
        return canonicalize(value)

    def propose(self, request):
        return {"intelligence_only": True, "request": dict(request)}

    def evaluate(self, proposal, context=None):
        request = dict(proposal.get("request", {}))
        action = request.get("action", "")
        resource = request.get("resource", "")
        if (
            action in {"authority.rotate", "audit.truncate", "exec.shell"}
            or ".." in str(resource).replace("\\", "/").split("/")
            or (str(resource).startswith("/") and action != "fs.write")
        ):
            outcome = "NON_TEN_XEITO"
        elif action == "fs.write":
            try:
                path = Path(str(resource))
                expected = request.get("resource_digest")
                safe = (
                    path.is_absolute()
                    and not path.is_symlink()
                    and path.is_file()
                    and hashlib.sha256(path.read_bytes()).hexdigest() == expected
                )
            except OSError:
                safe = False
            outcome = "TEN_XEITO" if safe else "NON_TEN_XEITO"
        elif not context or context.get("evidence_complete") is not True:
            outcome = "REQUIRE_XEITO"
        elif context.get("permitted") is not True:
            outcome = "NON_TEN_XEITO"
        else:
            outcome = "TEN_XEITO"
        return {"outcome": outcome, "proposal_digest": digest(proposal)}

    def _internal(self, request: Mapping[str, Any]) -> ActionRequest:
        request_digest = hashlib.sha256(canonicalize(dict(request))).hexdigest()
        relative = f"workspace/{request_digest}.bin"
        path = self.root / "resources" / relative
        if not path.exists():
            path.write_bytes(canonicalize(dict(request)))
        return ActionRequest(
            request_id="exam-" + request_digest[:40],
            principal="planner",
            audience="executor",
            action="resource.read",
            resource=relative,
            parameters={},
        )

    @staticmethod
    def _nonce(value: str) -> str:
        return hashlib.sha256(("mgk-exam-nonce:" + value).encode()).hexdigest()[:32]

    def _resign(self, envelope: bytes, **overrides) -> bytes:
        document = parse_canonical(envelope)
        payload = document["payload"]
        payload.update({key: value for key, value in overrides.items() if value is not None})
        base = dict(payload)
        base.pop("capability_id", None)
        payload["capability_id"] = digest(base)
        document["signature"] = sign(
            self.authority_key,
            CAPABILITY_DOMAIN,
            canonicalize(payload),
        )
        return canonicalize(document)

    def issue(
        self,
        request,
        *,
        scope: Sequence[str] | None = None,
        issued_at: int | None = None,
        expires_at: int | None = None,
        nonce: str | None = None,
        epoch: int | None = None,
    ):
        internal = self._internal(request)
        issued = self.authority.issue(internal)
        overrides = {
            "authorization_epoch": epoch,
            "expires_at": expires_at,
            "issued_at": issued_at,
            "nonce": self._nonce(nonce) if nonce is not None else None,
        }
        return self._resign(issued.envelope, **overrides)

    def verify(self, capability, request):
        try:
            payload = self.verifier.verify(capability, self._internal(request), consume_nonce=False)
            return {"authorized": True, "code": "AUTHORIZED", "claims": payload}
        except BaseException as exc:
            return {"authorized": False, "code": getattr(exc, "code", "DENIED")}

    def _failure(self, request, code):
        data = {
            "agent": "independent-exam",
            "attempt": 1,
            "base_sha": None,
            "code": code,
            "command": "Harness.execute",
            "diagnosis": "capability or execution boundary rejected the request",
            "evidence": code,
            "exit_code": 1,
            "failing_gate": "EXECUTION_AUTHORITY",
            "failure_class": "SECURITY_VIOLATION",
            "patch_sha256": None,
            "phase": "INDEPENDENT_EXAM",
            "remediation": "preserve denial and require a new valid capability",
            "result": "DENIED",
            "run_id": "independent-exam",
            "timestamp": self.clock.now(),
        }
        try:
            self.failures.record(data, self.clock.now())
        except BaseException:
            pass

    def execute(self, capability, request, operation, *, before_commit=None):
        try:
            self.audit.verify_integrity()
            self.failures.verify_integrity()
            internal = self._internal(request)
            payload = self.verifier.verify(capability, internal, consume_nonce=True)
            if before_commit is not None:
                before_commit()
            if payload["authorization_epoch"] != self.state.current_epoch():
                raise RuntimeError("EPOCH_CHANGED_BEFORE_COMMIT")
            self.guard.read_bound(payload["resource_binding"])
            if request.get("action") == "fs.write":
                path = Path(str(request.get("resource", "")))
                if path.is_symlink() or not path.is_file():
                    raise RuntimeError("TOCTOU_RESOURCE_REPLACED")
                actual = hashlib.sha256(path.read_bytes()).hexdigest()
                if actual != request.get("resource_digest"):
                    raise RuntimeError("TOCTOU_RESOURCE_REPLACED")
            operation()
            event = {
                "decision": "ALLOW",
                "epoch": payload["authorization_epoch"],
                "event": "EXECUTION",
                "feedback": {"observable": True},
                "nonce": payload["nonce"],
                "request_digest": hashlib.sha256(canonicalize(dict(request))).hexdigest(),
                "timestamp": self.clock.now(),
            }
            self.audit.append("INDEPENDENT_EXECUTION", event, self.clock.now())
            return {"executed": True, "code": "AUTHORIZED"}
        except BaseException as exc:
            code = getattr(exc, "code", type(exc).__name__)
            self._failure(request, code)
            try:
                self.audit.append(
                    "INDEPENDENT_DENIAL",
                    {
                        "decision": "DENY",
                        "event": "EXECUTION",
                        "feedback": {"observable": True},
                        "request_digest": hashlib.sha256(canonicalize(dict(request))).hexdigest(),
                        "timestamp": self.clock.now(),
                    },
                    self.clock.now(),
                )
            except BaseException:
                pass
            return {"executed": False, "code": code}

    def rotate_epoch(self):
        return self.state.bump_epoch(self.authority_key)

    def current_epoch(self):
        return self.state.current_epoch()

    @staticmethod
    def export_capability(capability):
        return bytes(capability)

    @staticmethod
    def import_capability(wire):
        return bytes(wire)

    @staticmethod
    def claims(capability):
        try:
            return parse_canonical(capability)["payload"]
        except BaseException:
            return {}

    @staticmethod
    def signature(capability):
        try:
            return b64u_decode(parse_canonical(capability)["signature"])
        except BaseException:
            return b""

    def assemble(self, claims, signature):
        return canonicalize(
            {
                "algorithm": "Ed25519",
                "key_id": key_id(self.authority_key.public_key()),
                "payload": dict(claims),
                "signature": b64u_encode(bytes(signature)),
            }
        )

    def authority_public_key(self):
        return self.authority_key.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )

    def planner_view(self):
        return SimpleNamespace(propose=self.propose)

    @staticmethod
    def _events(path):
        events = []
        for line in path.read_bytes().splitlines():
            try:
                record = parse_canonical(line)
                data = dict(record.get("data", {}))
                data.setdefault("event_type", record.get("event_type"))
                events.append(data)
            except BaseException:
                pass
        return events

    def audit_events(self):
        return self._events(self.audit.ledger_path)

    def failure_events(self):
        return self._events(self.failures.ledger_path)

    def audit_integrity(self):
        try:
            self.audit.verify_integrity()
            return {"valid": True, "code": "PASS"}
        except BaseException as exc:
            return {"valid": False, "code": getattr(exc, "code", "FAIL")}

    def corrupt_audit(self):
        raw = bytearray(self.audit.ledger_path.read_bytes())
        if raw:
            raw[len(raw) // 2] ^= 1
        else:
            raw.extend(b"corrupt\n")
        self.audit.ledger_path.write_bytes(bytes(raw))


def create_harness(root: Path, clock):
    return Harness(root, clock)
