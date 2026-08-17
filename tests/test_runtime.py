from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from mgk.crypto import b64u_encode

from runtime.config import RuntimeConfig
from runtime.decision import DecisionState
from runtime.sandbox import ACTUATOR_ACTIONS, validate_request
from runtime.workspace import Workspace


@pytest.fixture
def workspace(tmp_path):
    config = RuntimeConfig.from_workdir(tmp_path / "rt")
    return Workspace(config)


def make_request(request_id, action, resource, parameters=None):
    return {
        "request_id": request_id,
        "principal": "planner",
        "audience": "executor",
        "action": action,
        "resource": resource,
        "parameters": parameters or {},
    }


def test_workspace_initializes_keys_and_state(workspace):
    assert workspace.initialized is False
    bundle = workspace.create_runtime()
    assert workspace.initialized is True
    authority_key = workspace.keys_dir / "authority.key"
    assert authority_key.exists()
    assert (os.stat(authority_key).st_mode & 0o777) == 0o600
    assert (workspace.keys_dir / "authority.pub").read_text().startswith("ed25519:")
    assert (workspace.keys_dir / "audit.pub").read_text().startswith("ed25519:")
    assert (workspace.keys_dir / "operator.pub").read_text().startswith("ed25519:")
    assert bundle.state.current_epoch() == 1
    assert bundle.identity["authority"] == (workspace.keys_dir / "authority.pub").read_text().strip()


def test_workspace_hardens_directory_and_sqlite_permissions(workspace):
    workspace.create_runtime()
    assert (os.stat(workspace.root).st_mode & 0o777) == 0o700
    assert (os.stat(workspace.keys_dir).st_mode & 0o777) == 0o700
    assert (os.stat(workspace.state_path).st_mode & 0o777) == 0o600
    assert (os.stat(workspace.ledger_path).st_mode & 0o777) == 0o600


def test_safe_read_is_allowed_and_executed(workspace):
    bundle = workspace.create_runtime()
    (bundle.workspace.files_root / "hello.txt").write_bytes(b"hello\n")
    decision = bundle.pipeline.propose(make_request("r1", "sandbox.read_file", "files/hello.txt"))
    assert decision.state is DecisionState.ALLOW
    assert decision.executed is True
    assert decision.capability_id is not None
    assert decision.output_digest is not None


def test_sensitive_write_requires_human_then_approve_executes(workspace):
    bundle = workspace.create_runtime()
    decision = bundle.pipeline.propose(
        make_request(
            "r2",
            "sandbox.write_file",
            "files/note.txt",
            {"content_b64": b64u_encode(b"data")},
        )
    )
    assert decision.state is DecisionState.REQUIRE_HUMAN
    assert decision.executed is False
    pending = bundle.pipeline.pending()
    assert [row["request_id"] for row in pending] == ["r2"]
    approved = bundle.pipeline.human_approve("r2", "operator-alice")
    assert approved.state is DecisionState.ALLOW
    assert approved.executed is True
    assert (bundle.workspace.files_root / "note.txt").read_bytes() == b"data"
    assert bundle.pipeline.pending() == []
    human_actions = bundle.ledger.human_actions()
    assert len(human_actions) == 1
    assert human_actions[0]["decision"] == "APPROVE"
    assert human_actions[0]["signature"]


def test_append_requires_human_then_approve_appends(workspace):
    bundle = workspace.create_runtime()
    (bundle.workspace.files_root / "log.txt").write_bytes(b"line1\n")
    decision = bundle.pipeline.propose(
        make_request(
            "ap1",
            "sandbox.append_file",
            "files/log.txt",
            {"content_b64": b64u_encode(b"line2\n")},
        )
    )
    assert decision.state is DecisionState.REQUIRE_HUMAN
    assert decision.executed is False
    approved = bundle.pipeline.human_approve("ap1", "operator-alice")
    assert approved.state is DecisionState.ALLOW
    assert approved.executed is True
    assert (bundle.workspace.files_root / "log.txt").read_bytes() == b"line1\nline2\n"
    assert bundle.pipeline.pending() == []
    human_actions = bundle.ledger.human_actions()
    assert [row["request_id"] for row in human_actions] == ["ap1"]


def test_create_record_requires_human_then_approve_creates(workspace):
    bundle = workspace.create_runtime()
    decision = bundle.pipeline.propose(
        make_request(
            "cr1",
            "sandbox.create_record",
            "records/rec1",
            {"content_b64": b64u_encode(b'{"a": 1}')},
        )
    )
    assert decision.state is DecisionState.REQUIRE_HUMAN
    assert decision.executed is False
    approved = bundle.pipeline.human_approve("cr1", "operator-alice")
    assert approved.state is DecisionState.ALLOW
    assert approved.executed is True
    assert (bundle.workspace.records_root / "rec1").read_bytes() == b'{"a": 1}'


def test_human_deny_records_deny_and_no_side_effect(workspace):
    bundle = workspace.create_runtime()
    decision = bundle.pipeline.propose(
        make_request(
            "r3",
            "sandbox.create_record",
            "records/1",
            {"content_b64": b64u_encode(b'{"x": 1}')},
        )
    )
    assert decision.state is DecisionState.REQUIRE_HUMAN
    denied = bundle.pipeline.human_deny("r3", "operator-bob")
    assert denied.state is DecisionState.DENY
    assert denied.executed is False
    assert not (bundle.workspace.records_root / "1").exists()
    row = [r for r in bundle.ledger.decisions() if r["request_id"] == "r3"][0]
    assert row["state"] == "DENY"


def test_path_escape_is_clean_deny(workspace):
    bundle = workspace.create_runtime()
    decision = bundle.pipeline.propose(
        make_request("r4", "sandbox.read_file", "../etc/passwd")
    )
    assert decision.state is DecisionState.DENY
    assert decision.executed is False


def test_missing_resource_read_is_deny_not_indeterminate(workspace):
    bundle = workspace.create_runtime()
    decision = bundle.pipeline.propose(
        make_request("r5", "sandbox.read_file", "files/does-not-exist.txt")
    )
    assert decision.state is DecisionState.DENY
    assert decision.executed is False
    assert "RESOURCE_ERROR" in decision.reason_codes


def test_symlink_swap_before_approve_is_clean_deny(workspace):
    bundle = workspace.create_runtime()
    decision = bundle.pipeline.propose(
        make_request(
            "swap1",
            "sandbox.write_file",
            "files/swap.txt",
            {"content_b64": b64u_encode(b"malicious")},
        )
    )
    assert decision.state is DecisionState.REQUIRE_HUMAN
    target = bundle.workspace.files_root / "swap.txt"
    target.symlink_to("/etc/passwd")
    approved = bundle.pipeline.human_approve("swap1", "operator-alice")
    assert approved.state is DecisionState.DENY
    assert approved.executed is False
    assert "RESOURCE_ERROR" in approved.reason_codes


def test_non_canonical_content_is_denied_at_issue_time(workspace):
    bundle = workspace.create_runtime()
    decision = bundle.pipeline.propose(
        make_request("r6", "sandbox.write_file", "files/pad.txt", {"content_b64": "aGk="})
    )
    assert decision.state is DecisionState.REQUIRE_HUMAN
    approved = bundle.pipeline.human_approve("r6", "operator-alice")
    assert approved.state is DecisionState.DENY
    assert approved.executed is False
    assert not (bundle.workspace.files_root / "pad.txt").exists()


def test_unknown_action_is_denied(workspace):
    bundle = workspace.create_runtime()
    decision = bundle.pipeline.propose(
        make_request("r7", "process.exec", "files/x", {"command": "id"})
    )
    assert decision.state is DecisionState.DENY
    assert decision.executed is False


def test_deny_all_mode_denies_everything(workspace):
    bundle = workspace.create_runtime()
    from runtime.policy import RuntimePolicy

    bundle.pipeline.policy = RuntimePolicy(mode="deny_all")
    decision = bundle.pipeline.propose(make_request("r8", "sandbox.read_file", "files/hello.txt"))
    assert decision.state is DecisionState.DENY


def test_flight_recorder_integrity_holds(workspace):
    bundle = workspace.create_runtime()
    (bundle.workspace.files_root / "a.txt").write_bytes(b"a\n")
    bundle.pipeline.propose(make_request("f1", "sandbox.read_file", "files/a.txt"))
    bundle.pipeline.propose(
        make_request(
            "f2",
            "sandbox.write_file",
            "files/b.txt",
            {"content_b64": b64u_encode(b"b")},
        )
    )
    count, head = bundle.flight.verify_integrity()
    assert count >= 2
    assert head != "0" * 64
    events = [json.loads(line) for line in bundle.flight.path.open("rb")]
    types = {event["event_type"] for event in events}
    assert "DECISION_ALLOW" in types
    assert "DECISION_REQUIRE_HUMAN" in types
    for prev, event in zip(events, events[1:]):
        assert event["prev_hash"] == prev["event_hash"]


def test_audit_and_failure_ledgers_verify(workspace):
    bundle = workspace.create_runtime()
    (bundle.workspace.files_root / "ok.txt").write_bytes(b"x\n")
    bundle.pipeline.propose(make_request("l1", "sandbox.read_file", "files/ok.txt"))
    bundle.pipeline.propose(make_request("l2", "sandbox.read_file", "files/missing.txt"))
    audit_count, audit_head = bundle.audit.verify_integrity()
    assert audit_count >= 1
    assert audit_head != "0" * 64


def test_runtime_ledger_records_proposals_and_decisions(workspace):
    bundle = workspace.create_runtime()
    (bundle.workspace.files_root / "c.txt").write_bytes(b"c\n")
    bundle.pipeline.propose(make_request("p1", "sandbox.read_file", "files/c.txt"))
    bundle.pipeline.propose(make_request("p2", "sandbox.write_file", "files/d.txt", {"content_b64": b64u_encode(b"d")}))
    proposals = {p["request_id"] for p in bundle.ledger.proposals()}
    assert {"p1", "p2"} <= proposals
    states = {d["request_id"]: d["state"] for d in bundle.ledger.decisions()}
    assert states["p1"] == "ALLOW"
    assert states["p2"] == "REQUIRE_HUMAN"


def test_actuator_registry_is_closed_set():
    assert ACTUATOR_ACTIONS == frozenset(
        {
            "sandbox.read_file",
            "sandbox.write_file",
            "sandbox.append_file",
            "sandbox.create_record",
            "sandbox.read_record",
        }
    )
    validate_request(make_request("a1", "sandbox.write_file", "files/x.txt", {"content_b64": "Yg"}))
    with pytest.raises(ValueError):
        validate_request(make_request("a2", "process.exec", "files/x.txt", {}))
    with pytest.raises(ValueError):
        validate_request(make_request("a3", "sandbox.write_file", "records/x.txt", {"content_b64": "Yg"}))
    with pytest.raises(ValueError):
        validate_request(make_request("a4", "sandbox.write_file", "files/x.txt", {}))


def test_runtime_config_validation(tmp_path):
    with pytest.raises(ValueError):
        RuntimeConfig.from_workdir(tmp_path, port=10)
    with pytest.raises(ValueError):
        RuntimeConfig.from_workdir(tmp_path, ttl_seconds=9999)
    with pytest.raises(ValueError):
        RuntimeConfig.from_workdir(tmp_path, epoch=0)