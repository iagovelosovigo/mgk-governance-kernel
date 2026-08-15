from __future__ import annotations

import pytest

from api_contract import request
from tests.helpers import Counter


pytestmark = [pytest.mark.integration, pytest.mark.protected]


def test_denial_records_machine_readable_failure_fields(harness):
    req = request()
    invalid = harness.assemble({"garbage": True}, b"invalid")
    harness.execute(invalid, req, Counter().operation)
    event = harness.failure_events()[-1]
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
    assert required <= set(event), f"missing failure-ledger fields: {required - set(event)}"


def test_feedback_is_observable_after_allow_and_deny(harness):
    allow_req = request(resource="urn:mgk:test:feedback-allow")
    cap = harness.issue(allow_req, nonce="n-feedback-allow")
    harness.execute(cap, allow_req, Counter().operation)

    deny_req = request(resource="urn:mgk:test:feedback-deny")
    invalid = harness.assemble({"request": deny_req}, b"invalid")
    harness.execute(invalid, deny_req, Counter().operation)

    events = harness.audit_events()
    decisions = {event.get("decision") for event in events}
    assert {"ALLOW", "DENY"} <= decisions
    assert all("feedback" in event for event in events[-2:])

