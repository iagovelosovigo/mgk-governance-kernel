from __future__ import annotations

import copy

import pytest

from api_contract import request
from tests.helpers import Counter, assert_denied, mutated_capability


pytestmark = [pytest.mark.adversarial, pytest.mark.protected]


def test_signature_forgery_is_denied(harness):
    req = request()
    valid = harness.issue(req, nonce="n-forge-1")
    forged = harness.assemble(harness.claims(valid), b"\x00" * len(harness.signature(valid)))
    counter = Counter()
    assert_denied(harness.execute(forged, req, counter.operation), counter)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("action", "admin.delete"),
        ("resource", "urn:mgk:test:omega"),
        ("payload", {"value": "mutated"}),
        ("scope", ["*"]),
        ("epoch", 999_999),
        ("nonce", "attacker-replaced"),
        ("issued_at", 1),
        ("expires_at", 9_999_999_999),
    ],
)
def test_signed_claim_mutation_is_denied(harness, field, value):
    req = request(payload={"value": "original"})
    valid = harness.issue(req, scope=["kv.write"], nonce="n-mutation-1")
    tampered = mutated_capability(harness, valid, field, value)
    counter = Counter()
    assert_denied(harness.execute(tampered, req, counter.operation), counter)


def test_payload_substitution_with_valid_token_is_denied(harness):
    original = request(payload={"amount": 1})
    cap = harness.issue(original, nonce="n-payload-1")
    altered = request(payload={"amount": 1_000_000})
    counter = Counter()
    assert_denied(harness.execute(cap, altered, counter.operation), counter)


def test_resource_substitution_with_valid_token_is_denied(harness):
    original = request(resource="urn:mgk:test:alpha")
    cap = harness.issue(original, nonce="n-resource-1")
    altered = request(resource="urn:mgk:test:beta")
    counter = Counter()
    assert_denied(harness.execute(cap, altered, counter.operation), counter)


def test_scope_escalation_and_confused_deputy_are_denied(harness):
    read = request(action="kv.read")
    cap = harness.issue(read, scope=["kv.read"], nonce="n-scope-1")
    write = request(action="kv.write", resource=read["resource"])
    counter = Counter()
    assert_denied(harness.execute(cap, write, counter.operation), counter)


def test_public_key_is_not_secret_signing_material(harness):
    public = harness.authority_public_key()
    assert isinstance(public, bytes) and len(public) >= 32
    req = request()
    claims = copy.deepcopy(dict(harness.claims(harness.issue(req, nonce="n-pub-1"))))
    forged = harness.assemble(claims, public[:64])
    counter = Counter()
    assert_denied(harness.execute(forged, req, counter.operation), counter)


def test_audit_tampering_forces_fail_closed(harness):
    first = request(resource="urn:mgk:test:first")
    cap1 = harness.issue(first, nonce="n-audit-1")
    harness.execute(cap1, first, Counter().operation)
    harness.corrupt_audit()
    assert harness.audit_integrity().get("valid") is False

    second = request(resource="urn:mgk:test:second")
    try:
        cap2 = harness.issue(second, nonce="n-audit-2")
    except (ValueError, RuntimeError):
        assert harness.failure_events(), "audit corruption refusal lost its evidence"
        return
    counter = Counter()
    assert_denied(harness.execute(cap2, second, counter.operation), counter)


def test_operation_exception_never_reports_execution_success(harness):
    req = request()
    cap = harness.issue(req, nonce="n-exception-1")

    def explode():
        raise RuntimeError("hostile operation")

    result = harness.execute(cap, req, explode)
    assert result.get("executed") is False
    assert result.get("code")
    assert harness.failure_events(), "exception evidence was lost"
