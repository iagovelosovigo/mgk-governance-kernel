from __future__ import annotations

import pytest

from api_contract import request
from tests.helpers import Counter, assert_authorized, assert_denied


pytestmark = [pytest.mark.integration, pytest.mark.protected]


def test_valid_capability_executes_exactly_once_and_audits(harness):
    req = request(payload={"value": 42})
    cap = harness.issue(req, scope=["kv.write"], nonce="n-valid-1")
    assert harness.verify(cap, req).get("authorized") is True

    counter = Counter()
    assert_authorized(harness.execute(cap, req, counter.operation), counter)

    events = harness.audit_events()
    assert events, "successful execution must be audited"
    event = events[-1]
    for field in ("timestamp", "event", "decision", "request_digest", "nonce", "epoch"):
        assert field in event, f"missing audit field: {field}"
    assert event["decision"] == "ALLOW"
    assert harness.audit_integrity().get("valid") is True


def test_invalid_capability_denies_and_preserves_failure_evidence(harness):
    req = request()
    bad = harness.assemble(
        {"action": req["action"], "resource": req["resource"]}, b"bad"
    )
    counter = Counter()
    assert_denied(harness.execute(bad, req, counter.operation), counter)
    failures = harness.failure_events()
    assert failures, "denial must preserve failure evidence"
    assert failures[-1].get("failure_class")
    assert failures[-1].get("code")


def test_authorization_epoch_rotation_invalidates_prior_capability(harness):
    req = request()
    old_epoch = harness.current_epoch()
    cap = harness.issue(req, nonce="n-epoch-1", epoch=old_epoch)
    new_epoch = harness.rotate_epoch()
    assert new_epoch > old_epoch
    counter = Counter()
    assert_denied(harness.execute(cap, req, counter.operation), counter)


def test_expiry_checked_at_execution_not_only_at_issue(harness, clock):
    req = request()
    cap = harness.issue(
        req,
        nonce="n-expiry-1",
        issued_at=clock.now,
        expires_at=clock.now + 2,
    )
    assert harness.verify(cap, req).get("authorized") is True
    clock.advance(3)
    counter = Counter()
    assert_denied(harness.execute(cap, req, counter.operation), counter)


def test_future_issued_at_is_denied(harness, clock):
    req = request()
    try:
        cap = harness.issue(
            req,
            nonce="n-future-1",
            issued_at=clock.now + 60,
            expires_at=clock.now + 120,
        )
    except (ValueError, RuntimeError):
        return
    counter = Counter()
    assert_denied(harness.execute(cap, req, counter.operation), counter)
