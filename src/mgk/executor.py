"""Capability-only executor. No planner output is executable without valid authority."""

from __future__ import annotations

from typing import Any

from .clock import SystemClock
from .crypto import b64u_decode
from .errors import MGKError
from .ledger import AuditLedger, FailureLedger
from .models import ActionRequest, ExecutionResult
from .resource import ResourceGuard
from .verifier import CapabilityVerifier


class CapabilityExecutor:
    def __init__(
        self,
        executor_id: str,
        verifier: CapabilityVerifier,
        resource_guard: ResourceGuard,
        audit_ledger: AuditLedger,
        failure_ledger: FailureLedger,
        clock: object | None = None,
    ):
        self.executor_id = executor_id
        self.verifier = verifier
        self.resource_guard = resource_guard
        self.audit_ledger = audit_ledger
        self.failure_ledger = failure_ledger
        self.clock = clock or SystemClock()

    @staticmethod
    def _code(exc: BaseException) -> str:
        return exc.code if isinstance(exc, MGKError) else "UNEXPECTED_EXCEPTION"

    def _record_denial(self, request: ActionRequest, code: str, capability_id: str | None) -> None:
        data = {
            "agent": "capability-executor",
            "action": request.action,
            "attempt": 1,
            "base_sha": None,
            "capability_id": capability_id,
            "code": code,
            "command": "CapabilityExecutor.execute",
            "diagnosis": "authority boundary rejected or could not safely complete the request",
            "evidence": code,
            "exit_code": 1,
            "failing_gate": "EXECUTION_AUTHORITY",
            "failure_class": "SECURITY_VIOLATION" if code != "UNEXPECTED_EXCEPTION" else "UNKNOWN",
            "model_provider": None,
            "patch_sha256": None,
            "phase": "RUNTIME_EXECUTION",
            "reason_code": code,
            "remediation": "preserve evidence and require a fresh valid capability",
            "request_id": request.request_id,
            "resource": request.resource,
            "result": "DENIED",
            "run_id": request.request_id,
            "timestamp": self.clock.now(),
        }
        now = self.clock.now()
        try:
            self.failure_ledger.record(data, now)
        except BaseException:
            pass
        try:
            self.audit_ledger.append("EXECUTION_DENIED", data, now)
        except BaseException:
            pass

    def execute(self, envelope_bytes: bytes, request: ActionRequest) -> ExecutionResult:
        capability_id: str | None = None
        try:
            if request.audience != self.executor_id:
                raise ValueError("executor audience mismatch")
            self.audit_ledger.verify_integrity()
            self.failure_ledger.verify_integrity()
            self.verifier.state.integrity_check()
            payload = self.verifier.verify(envelope_bytes, request, consume_nonce=True)
            capability_id = payload["capability_id"]
            intent = {
                "action": request.action,
                "capability_id": capability_id,
                "request_id": request.request_id,
                "resource": request.resource,
            }
            self.audit_ledger.append("EXECUTION_AUTHORIZED", intent, self.clock.now())

            if payload["authorization_epoch"] != self.verifier.state.current_epoch():
                from .errors import EpochError

                raise EpochError("authorization epoch changed before commit")

            if request.action == "resource.read":
                output = self.resource_guard.read_bound(payload["resource_binding"])
                import hashlib

                output_digest = hashlib.sha256(output).hexdigest()
            elif request.action == "resource.create":
                data = b64u_decode(dict(request.parameters)["content_b64"])
                output_digest = self.resource_guard.create_bound(payload["resource_binding"], data)
                output = None
            elif request.action in {"sandbox.read_file", "sandbox.read_record"}:
                output = self.resource_guard.read_bound(payload["resource_binding"])
                import hashlib

                output_digest = hashlib.sha256(output).hexdigest()
            elif request.action == "sandbox.write_file":
                data = b64u_decode(dict(request.parameters)["content_b64"])
                output_digest = self.resource_guard.write_bound(payload["resource_binding"], data)
                output = None
            elif request.action == "sandbox.append_file":
                data = b64u_decode(dict(request.parameters)["content_b64"])
                output_digest = self.resource_guard.append_bound(payload["resource_binding"], data)
                output = None
            elif request.action == "sandbox.create_record":
                data = b64u_decode(dict(request.parameters)["content_b64"])
                output_digest = self.resource_guard.create_bound(payload["resource_binding"], data)
                output = None
            else:
                raise ValueError("unsupported executor action")

            completed = dict(intent)
            completed["output_digest"] = output_digest
            try:
                self.audit_ledger.append("EXECUTION_COMPLETED", completed, self.clock.now())
            except BaseException:
                if request.action in {"resource.create", "sandbox.create_record"}:
                    self.resource_guard.remove_created(payload["resource_binding"], output_digest)
                raise
            return ExecutionResult(
                success=True,
                status="EXECUTED",
                reason_code="TEN_XEITO_AUTHORIZED",
                execution_authority=1,
                capability_id=capability_id,
                output_digest=output_digest,
                output=output,
            )
        except BaseException as exc:
            code = self._code(exc)
            self._record_denial(request, code, capability_id)
            return ExecutionResult(
                success=False,
                status="DENIED",
                reason_code=code,
                execution_authority=0,
                capability_id=capability_id,
            )
