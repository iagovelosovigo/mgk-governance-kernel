from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import threading

import pytest

from api_contract import request
from tests.helpers import Counter


pytestmark = [pytest.mark.concurrency, pytest.mark.replay, pytest.mark.protected]


def test_concurrent_replay_has_at_most_one_winner(harness):
    req = request()
    cap = harness.issue(req, nonce="n-concurrent-1")
    workers = 32
    barrier = threading.Barrier(workers)
    counter = Counter()

    def attempt():
        barrier.wait(timeout=10)
        return harness.execute(cap, req, counter.operation)

    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = list(pool.map(lambda _: attempt(), range(workers)))

    assert sum(result.get("executed") is True for result in results) == 1
    assert counter.value == 1
    assert all(result.get("executed") in {True, False} for result in results)
    assert all(result.get("code") for result in results)


def test_epoch_rotation_during_commit_invalidates_execution(harness):
    req = request()
    cap = harness.issue(req, nonce="n-epoch-race-1", epoch=harness.current_epoch())
    counter = Counter()
    result = harness.execute(
        cap,
        req,
        counter.operation,
        before_commit=lambda: harness.rotate_epoch(),
    )
    assert result.get("executed") is False
    assert counter.value == 0


def test_concurrent_unique_capabilities_preserve_audit_chain(harness):
    total = 24
    barrier = threading.Barrier(total)

    def attempt(index: int):
        req = request(resource=f"urn:mgk:test:{index}")
        cap = harness.issue(req, nonce=f"n-unique-{index}")
        counter = Counter()
        barrier.wait(timeout=10)
        result = harness.execute(cap, req, counter.operation)
        return result, counter.value

    with ThreadPoolExecutor(max_workers=total) as pool:
        outcomes = list(pool.map(attempt, range(total)))

    assert all(result.get("executed") is True and count == 1 for result, count in outcomes)
    assert harness.audit_integrity().get("valid") is True

