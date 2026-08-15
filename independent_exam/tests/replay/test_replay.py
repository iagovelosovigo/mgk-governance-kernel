from __future__ import annotations

import pytest

from api_contract import request
from tests.helpers import Counter, assert_authorized, assert_denied


pytestmark = [pytest.mark.replay, pytest.mark.protected]


def test_sequential_replay_is_denied(harness):
    req = request()
    cap = harness.issue(req, nonce="n-replay-1")
    first = Counter()
    assert_authorized(harness.execute(cap, req, first.operation), first)
    second = Counter()
    assert_denied(harness.execute(cap, req, second.operation), second)


def test_reimporting_same_wire_does_not_reset_replay_state(harness):
    req = request()
    cap = harness.issue(req, nonce="n-replay-wire-1")
    wire = harness.export_capability(cap)
    first_token = harness.import_capability(wire)
    second_token = harness.import_capability(wire)
    first = Counter()
    assert_authorized(harness.execute(first_token, req, first.operation), first)
    second = Counter()
    assert_denied(harness.execute(second_token, req, second.operation), second)


def test_operation_failure_does_not_restore_nonce(harness):
    req = request()
    cap = harness.issue(req, nonce="n-failed-op-1")

    def fail():
        raise RuntimeError("operation failed after authorization")

    first = harness.execute(cap, req, fail)
    assert first.get("executed") is False
    retry = Counter()
    assert_denied(harness.execute(cap, req, retry.operation), retry)


def test_duplicate_nonce_cannot_authorize_twice(harness):
    first_req = request(resource="urn:mgk:test:first")
    second_req = request(resource="urn:mgk:test:second")
    first = harness.issue(first_req, nonce="n-duplicate-1")
    try:
        second = harness.issue(second_req, nonce="n-duplicate-1")
    except (ValueError, RuntimeError):
        return
    counter1 = Counter()
    result1 = harness.execute(first, first_req, counter1.operation)
    counter2 = Counter()
    result2 = harness.execute(second, second_req, counter2.operation)
    assert int(result1.get("executed") is True) + int(result2.get("executed") is True) <= 1
    assert counter1.value + counter2.value <= 1

