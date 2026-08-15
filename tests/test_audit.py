import json
import sqlite3

import pytest

from mgk.errors import AuditIntegrityError, StateIntegrityError
from mgk import SecurityState
from mgk.crypto import b64u_encode
from mgk.canonical import parse_canonical
from mgk.models import ActionRequest

from .helpers import read_request


def execute_once(kernel):
    request = read_request()
    issued = kernel.authority.issue(request)
    assert kernel.executor.execute(issued.envelope, request).success


def test_audit_event_mutation_is_detected(kernel_factory):
    kernel = kernel_factory()
    execute_once(kernel)
    raw = bytearray(kernel.audit.ledger_path.read_bytes())
    raw[len(raw) // 2] ^= 1
    kernel.audit.ledger_path.write_bytes(bytes(raw))
    with pytest.raises(AuditIntegrityError):
        kernel.audit.verify_integrity()


def test_audit_tail_deletion_is_detected(kernel_factory):
    kernel = kernel_factory()
    execute_once(kernel)
    lines = kernel.audit.ledger_path.read_bytes().splitlines(keepends=True)
    kernel.audit.ledger_path.write_bytes(b"".join(lines[:-1]))
    with pytest.raises(AuditIntegrityError):
        kernel.audit.verify_integrity()


def test_checkpoint_tampering_is_detected(kernel_factory):
    kernel = kernel_factory()
    execute_once(kernel)
    raw = bytearray(kernel.audit.checkpoint_path.read_bytes())
    raw[len(raw) // 2] ^= 1
    kernel.audit.checkpoint_path.write_bytes(bytes(raw))
    with pytest.raises(AuditIntegrityError):
        kernel.audit.verify_integrity()


def test_corrupt_audit_denies_before_execution(kernel_factory):
    kernel = kernel_factory()
    request = read_request()
    issued = kernel.authority.issue(request)
    kernel.audit.ledger_path.write_bytes(b"corrupt\n")
    result = kernel.executor.execute(issued.envelope, request)
    assert result.success is False
    assert result.execution_authority == 0
    assert kernel.state.nonce_count() == 0


def test_failure_ledger_records_denial(kernel_factory):
    kernel = kernel_factory()
    request = read_request()
    issued = kernel.authority.issue(request)
    assert kernel.executor.execute(issued.envelope, request).success
    assert not kernel.executor.execute(issued.envelope, request).success
    count, _head = kernel.failures.verify_integrity()
    assert count == 1
    event = parse_canonical(kernel.failures.ledger_path.read_bytes().splitlines()[-1])["data"]
    required = {
        "timestamp",
        "run_id",
        "phase",
        "attempt",
        "base_sha",
        "patch_sha256",
        "agent",
        "command",
        "exit_code",
        "failing_gate",
        "failure_class",
        "evidence",
        "diagnosis",
        "remediation",
        "result",
        "code",
    }
    assert required <= set(event)


def test_security_state_corruption_fails_closed(kernel_factory):
    kernel = kernel_factory()
    request = read_request()
    issued = kernel.authority.issue(request)
    with kernel.state.path.open("r+b") as stream:
        stream.seek(0)
        stream.write(b"not sqlite")
        stream.flush()
    result = kernel.executor.execute(issued.envelope, request)
    assert result.success is False
    assert result.execution_authority == 0


def test_external_epoch_floor_detects_signed_database_rollback(kernel_factory):
    kernel = kernel_factory()
    snapshot = kernel.root / "epoch-1.sqlite"
    with sqlite3.connect(kernel.state.path) as source, sqlite3.connect(snapshot) as target:
        source.backup(target)
    assert kernel.state.bump_epoch(kernel.authority_key) == 2
    rolled_back = SecurityState(snapshot, kernel.authority_key.public_key(), expected_minimum_epoch=2)
    with pytest.raises(Exception):
        rolled_back.current_epoch()


def test_post_effect_audit_failure_rolls_back_create(kernel_factory):
    kernel = kernel_factory()
    request = ActionRequest(
        "create-audit-failure",
        "planner",
        "executor",
        "resource.create",
        "workspace/audit-failure.txt",
        {"content_b64": b64u_encode(b"must rollback")},
    )
    issued = kernel.authority.issue(request)
    original_append = kernel.audit.append

    def injected(event_type, data, timestamp):
        if event_type == "EXECUTION_COMPLETED":
            raise OSError("injected completion audit failure")
        return original_append(event_type, data, timestamp)

    kernel.audit.append = injected
    result = kernel.executor.execute(issued.envelope, request)
    assert result.success is False
    assert result.execution_authority == 0
    assert not (kernel.root / "resources/workspace/audit-failure.txt").exists()
