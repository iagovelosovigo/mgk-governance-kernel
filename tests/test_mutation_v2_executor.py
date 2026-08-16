from __future__ import annotations

import hashlib

import pytest

from mgk import ActionRequest
from mgk.canonical import parse_canonical
from mgk.crypto import b64u_encode
from mgk.models import ExecutionResult

from .conftest import SAFE_CONTEXT
from .helpers import read_request


def _denial_record(kernel):
    count, _ = kernel.failures.verify_integrity()
    assert count == 1
    line = parse_canonical(kernel.failures.ledger_path.read_bytes().splitlines()[-1])
    assert line["event_type"] == "FAILURE"
    return line["data"]


def test_executor_success_result_exact_fields(kernel_factory):
    kernel = kernel_factory()
    request = read_request()
    issued = kernel.authority.issue(request)
    result = kernel.executor.execute(issued.envelope, request)
    assert isinstance(result, ExecutionResult)
    assert result.success is True
    assert result.status == "EXECUTED"
    assert result.reason_code == "TEN_XEITO_AUTHORIZED"
    assert result.execution_authority == 1
    assert result.capability_id == issued.capability_id
    assert result.output == b"allowed payload\n"
    assert result.output_digest == hashlib.sha256(b"allowed payload\n").hexdigest()


def test_executor_denial_result_exact_fields(kernel_factory):
    kernel = kernel_factory()
    request = read_request()
    issued = kernel.authority.issue(request)
    assert kernel.executor.execute(issued.envelope, request).success
    replay = kernel.executor.execute(issued.envelope, request)
    assert replay.success is False
    assert replay.status == "DENIED"
    assert replay.reason_code == "REPLAY_ERROR"
    assert replay.execution_authority == 0
    assert replay.capability_id is None
    assert replay.output is None
    assert replay.output_digest is None


def test_executor_denial_record_exact_fields(kernel_factory):
    kernel = kernel_factory()
    request = read_request()
    issued = kernel.authority.issue(request)
    assert kernel.executor.execute(issued.envelope, request).success
    assert not kernel.executor.execute(issued.envelope, request).success
    data = _denial_record(kernel)
    assert data["agent"] == "capability-executor"
    assert data["action"] == "resource.read"
    assert data["attempt"] == 1
    assert data["base_sha"] is None
    assert data["capability_id"] is None
    assert data["code"] == "REPLAY_ERROR"
    assert data["command"] == "CapabilityExecutor.execute"
    assert data["diagnosis"] == "authority boundary rejected or could not safely complete the request"
    assert data["evidence"] == "REPLAY_ERROR"
    assert data["exit_code"] == 1
    assert data["failing_gate"] == "EXECUTION_AUTHORITY"
    assert data["failure_class"] == "SECURITY_VIOLATION"
    assert data["model_provider"] is None
    assert data["patch_sha256"] is None
    assert data["phase"] == "RUNTIME_EXECUTION"
    assert data["reason_code"] == "REPLAY_ERROR"
    assert data["remediation"] == "preserve evidence and require a fresh valid capability"
    assert data["request_id"] == "request-1"
    assert data["resource"] == "workspace/allowed.txt"
    assert data["result"] == "DENIED"
    assert data["run_id"] == "request-1"
    assert data["timestamp"] == kernel.clock.now()


def test_executor_audit_records_exact_intents(kernel_factory):
    kernel = kernel_factory()
    request = read_request()
    issued = kernel.authority.issue(request)
    assert kernel.executor.execute(issued.envelope, request).success
    records = [parse_canonical(l) for l in kernel.audit.ledger_path.read_bytes().splitlines()]
    event_types = [r["event_type"] for r in records]
    assert event_types == ["EXECUTION_AUTHORIZED", "EXECUTION_COMPLETED"]
    intent = {
        "action": "resource.read",
        "capability_id": issued.capability_id,
        "request_id": "request-1",
        "resource": "workspace/allowed.txt",
    }
    assert records[0]["data"] == intent
    completed = dict(intent)
    completed["output_digest"] = hashlib.sha256(b"allowed payload\n").hexdigest()
    assert records[1]["data"] == completed


def test_executor_denial_audit_record_exact(kernel_factory):
    kernel = kernel_factory()
    request = read_request()
    issued = kernel.authority.issue(request)
    assert kernel.executor.execute(issued.envelope, request).success
    assert not kernel.executor.execute(issued.envelope, request).success
    records = [parse_canonical(l) for l in kernel.audit.ledger_path.read_bytes().splitlines()]
    assert records[-1]["event_type"] == "EXECUTION_DENIED"
    data = records[-1]["data"]
    assert data["code"] == "REPLAY_ERROR"
    assert data["result"] == "DENIED"
    assert data["exit_code"] == 1
    assert data["failing_gate"] == "EXECUTION_AUTHORITY"


def test_executor_audience_mismatch_is_unexpected_exception(kernel_factory):
    kernel = kernel_factory()
    valid = read_request()
    issued = kernel.authority.issue(valid)
    wrong = ActionRequest(
        "request-1",
        "planner",
        "not-executor",
        "resource.read",
        "workspace/allowed.txt",
        {},
    )
    result = kernel.executor.execute(issued.envelope, wrong)
    assert result.success is False
    assert result.reason_code == "UNEXPECTED_EXCEPTION"
    data = _denial_record(kernel)
    assert data["code"] == "UNEXPECTED_EXCEPTION"
    assert data["failure_class"] == "UNKNOWN"
    assert data["diagnosis"] == "authority boundary rejected or could not safely complete the request"


def test_executor_unsupported_action_is_denied(kernel_factory):
    kernel = kernel_factory()
    request = ActionRequest(
        "req-unsupported",
        "planner",
        "executor",
        "process.exec",
        "workspace/allowed.txt",
        {"command": "id"},
    )
    with pytest.raises(Exception):
        kernel.authority.issue(request)
    result = kernel.executor.execute(b"", request)
    assert result.success is False
    assert result.reason_code == "CANONICALIZATION_ERROR"
    assert result.execution_authority == 0


def test_executor_create_success_exact(kernel_factory):
    kernel = kernel_factory()
    data = b"created payload"
    request = ActionRequest(
        "req-create",
        "planner",
        "executor",
        "resource.create",
        "workspace/created.txt",
        {"content_b64": b64u_encode(data)},
    )
    issued = kernel.authority.issue(request)
    result = kernel.executor.execute(issued.envelope, request)
    assert result.success is True
    assert result.status == "EXECUTED"
    assert result.output is None
    assert result.output_digest == hashlib.sha256(data).hexdigest()
    assert (kernel.root / "resources/workspace/created.txt").read_bytes() == data


def test_executor_create_denial_no_side_effect(kernel_factory):
    kernel = kernel_factory()
    data = b"payload"
    request = ActionRequest(
        "req-create",
        "planner",
        "executor",
        "resource.create",
        "workspace/created.txt",
        {"content_b64": b64u_encode(data)},
    )
    issued = kernel.authority.issue(request)
    assert kernel.executor.execute(issued.envelope, request).success
    target = kernel.root / "resources/workspace/created.txt"
    assert target.read_bytes() == data
    replay = kernel.executor.execute(issued.envelope, request)
    assert replay.success is False
    assert replay.reason_code == "REPLAY_ERROR"
    assert target.read_bytes() == data


def test_action_request_to_payload_exact():
    request = ActionRequest("r", "p", "a", "resource.read", "workspace/f.txt", {"k": 1})
    assert request.to_payload() == {
        "action": "resource.read",
        "audience": "a",
        "parameters": {"k": 1},
        "principal": "p",
        "request_id": "r",
        "resource": "workspace/f.txt",
    }
    assert request.digest()


def test_action_request_rejects_non_mapping_parameters():
    with pytest.raises(TypeError, match="^parameters must be a mapping$"):
        ActionRequest("r", "p", "a", "resource.read", "workspace/f.txt", None).to_payload()


def test_saxp_context_to_payload_exact():
    assert SAFE_CONTEXT.to_payload() == {
        "coherence_delta": 100,
        "control_risk": False,
        "critical_uncertainty": False,
        "ethical_constraints_satisfied": True,
        "information_complete": True,
        "sentidino": 9000,
        "systemic_pressure": 10,
        "threshold_k": 100,
    }


def test_saxp_decision_to_payload_exact(kernel_factory):
    kernel = kernel_factory()
    request = read_request()
    decision = kernel.authority.saxp.evaluate(request, SAFE_CONTEXT)
    payload = decision.to_payload()
    assert set(payload) == {"context_digest", "policy_id", "reason_codes", "request_digest", "result"}
    assert payload["result"] == "TEN_XEITO"
    assert payload["policy_id"] == "saxp-level1-v1"
    assert payload["reason_codes"] == ["COHERENCE_GATE_SATISFIED"]