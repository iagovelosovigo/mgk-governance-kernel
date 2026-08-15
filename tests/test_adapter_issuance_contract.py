from __future__ import annotations

import hashlib
import sys
import threading
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import candidate_adapter


class FrozenClock:
    def __init__(self, now: int = 1_700_000_000) -> None:
        self.now = now


class Counter:
    def __init__(self) -> None:
        self.value = 0
        self._lock = threading.Lock()

    def operation(self) -> int:
        with self._lock:
            self.value += 1
            return self.value


def request(*, action: str = "kv.write", resource: str = "urn:mgk:test:alpha", payload=None) -> dict:
    return {"action": action, "resource": resource, "payload": {} if payload is None else payload}


@pytest.fixture
def harness(tmp_path):
    return candidate_adapter.create_harness(tmp_path, FrozenClock())


def test_regression_falsifying_example_resource_slash(harness):
    req = request(action="0", resource="/", payload=None)
    cap = harness.issue(req)
    assert cap
    changed = request(action="0", resource="/#changed", payload=None)
    counter = Counter()
    result = harness.execute(cap, changed, counter.operation)
    assert result.get("executed") is False
    assert counter.value == 0


EDGE_CASES = [
    request(action="0", resource="/", payload=None),
    request(action="fs.write", resource="/etc/passwd", payload={}),
    request(action="authority.rotate", resource="urn:mgk:authority:root", payload={}),
    request(action="audit.truncate", resource="urn:mgk:audit:ledger", payload={"n": 1}),
    request(action="exec.shell", resource="urn:host:/bin/sh", payload={"cmd": "id"}),
    request(action="kv.write", resource="../escape", payload={"x": 1}),
    request(action="fs.write", resource="../../root-of-trust", payload={"cmd": "id"}),
    request(action="a" * 32, resource="/" + "b" * 63, payload={"deep": {"list": [1, 2, 3]}}),
]


@pytest.mark.parametrize("edge", EDGE_CASES)
def test_issue_succeeds_for_arbitrary_request(harness, edge):
    cap = harness.issue(edge, nonce="n-edge-" + edge["resource"][:16])
    assert cap
    changed = dict(edge)
    changed["resource"] = changed["resource"] + "#changed"
    counter = Counter()
    result = harness.execute(cap, changed, counter.operation)
    assert result.get("executed") is False
    assert counter.value == 0


def test_saxp_policy_still_denies_path_traversal(harness):
    req = request(action="fs.write", resource="../../authority/private-key")
    decision = harness.evaluate(
        harness.propose(req), {"permitted": True, "evidence_complete": True}
    )
    assert decision.get("outcome") == "NON_TEN_XEITO"


def test_fs_write_toctou_between_verify_and_commit_still_denied(harness, tmp_path):
    victim = tmp_path / "victim"
    replacement = tmp_path / "replacement"
    victim.write_text("authorized", encoding="utf-8")
    replacement.write_text("forbidden", encoding="utf-8")
    req = request(
        action="fs.write",
        resource=str(victim),
        payload={},
    )
    req["resource_digest"] = hashlib.sha256(victim.read_bytes()).hexdigest()
    cap = harness.issue(req, nonce="n-reg-toctou")

    def replace():
        victim.unlink()
        victim.symlink_to(replacement)

    counter = Counter()
    result = harness.execute(cap, req, counter.operation, before_commit=replace)
    assert result.get("executed") is False
    assert counter.value == 0


def test_valid_capability_still_executes_exactly_once(harness):
    req = request(payload={"value": 42})
    cap = harness.issue(req, nonce="n-reg-valid")
    assert harness.verify(cap, req).get("authorized") is True
    counter = Counter()
    result = harness.execute(cap, req, counter.operation)
    assert result.get("executed") is True
    assert counter.value == 1
