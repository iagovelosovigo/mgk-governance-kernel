from __future__ import annotations

import hashlib

import pytest

from mgk import (
    ActionRequest,
    AuthorityPolicy,
    CapabilityAuthority,
    SAXPContext,
    SAXPEvaluator,
)
from mgk.canonical import canonicalize, digest, parse_canonical
from mgk.crypto import CAPABILITY_DOMAIN, generate_private_key, sign
from mgk.errors import (
    EpochError,
    ReplayError,
    SchemaError,
    ScopeError,
    TimeWindowError,
)

from .conftest import SAFE_CONTEXT
from .helpers import read_request


def _rebuild(kernel, request, overrides, action=None, binding=None):
    decision = kernel.authority.saxp.evaluate(request, SAFE_CONTEXT)
    if binding is None and request.action == "resource.read":
        binding = kernel.guard.bind_present(request.resource)
    base = {
        "audience": request.audience,
        "authorization_epoch": 1,
        "expires_at": kernel.clock.now() + 300,
        "issued_at": kernel.clock.now(),
        "issuer": "authority",
        "nonce": "0" * 32,
        "request_digest": request.digest(),
        "resource_binding": binding or {"path": request.resource, "state": "present"},
        "saxp": decision.to_payload(),
        "schema": "mgk-capability/v1",
        "scope": {"action": action or request.action, "resource": request.resource},
        "subject": request.principal,
    }
    base.update(overrides)
    capability_id = digest(base)
    payload = dict(base)
    payload["capability_id"] = capability_id
    envelope = canonicalize(
        {
            "algorithm": "Ed25519",
            "key_id": "ed25519:"
            + hashlib.sha256(kernel.authority_key.public_key().public_bytes_raw()).hexdigest(),
            "payload": payload,
            "signature": sign(kernel.authority_key, CAPABILITY_DOMAIN, canonicalize(payload)),
        }
    )
    return envelope


def test_verifier_verify_returns_payload_dict(kernel_factory):
    kernel = kernel_factory()
    request = read_request()
    issued = kernel.authority.issue(request)
    payload = kernel.verifier.verify(issued.envelope, request)
    assert isinstance(payload, dict)
    assert set(payload) == {
        "audience",
        "authorization_epoch",
        "capability_id",
        "expires_at",
        "issued_at",
        "issuer",
        "nonce",
        "request_digest",
        "resource_binding",
        "saxp",
        "schema",
        "scope",
        "subject",
    }
    assert payload["subject"] == "planner"
    assert payload["audience"] == "executor"
    assert payload["schema"] == "mgk-capability/v1"
    assert payload["authorization_epoch"] == 1
    assert payload["issuer"] == "authority"
    assert payload["scope"] == {"action": "resource.read", "resource": "workspace/allowed.txt"}
    assert payload["capability_id"] == issued.capability_id
    assert kernel.state.nonce_count() == 1
    with pytest.raises(ReplayError, match="^nonce was already consumed$"):
        kernel.verifier.verify(issued.envelope, request)


def test_verifier_rejects_invalid_envelope(kernel_factory):
    kernel = kernel_factory()
    request = read_request()
    bad = canonicalize({"not": "an envelope"})
    with pytest.raises(SchemaError, match="^invalid capability envelope$"):
        kernel.verifier.verify(bad, request)


def test_verifier_rejects_unexpected_signer(kernel_factory):
    kernel = kernel_factory()
    request = read_request()
    issued = kernel.authority.issue(request)
    envelope = parse_canonical(issued.envelope)
    envelope["key_id"] = "ed25519:" + "0" * 64
    with pytest.raises(SchemaError, match="^unexpected capability signer$"):
        kernel.verifier.verify(canonicalize(envelope), request)


def test_verifier_rejects_non_integer_timestamps(kernel_factory):
    kernel = kernel_factory()
    request = read_request()
    envelope = _rebuild(kernel, request, {"issued_at": "2000000000"})
    with pytest.raises(TimeWindowError, match="^capability timestamps must be integers$"):
        kernel.verifier.verify(envelope, request)


def test_verifier_rejects_invalid_validity_window(kernel_factory):
    kernel = kernel_factory()
    request = read_request()
    now = kernel.clock.now()
    envelope = _rebuild(kernel, request, {"issued_at": now, "expires_at": now})
    with pytest.raises(TimeWindowError, match="^invalid capability validity window$"):
        kernel.verifier.verify(envelope, request)
    envelope = _rebuild(kernel, request, {"issued_at": now, "expires_at": now + 301})
    with pytest.raises(TimeWindowError, match="^invalid capability validity window$"):
        kernel.verifier.verify(envelope, request)


def test_verifier_rejects_not_currently_valid(kernel_factory):
    kernel = kernel_factory()
    request = read_request()
    now = kernel.clock.now()
    future = _rebuild(kernel, request, {"issued_at": now + 6, "expires_at": now + 306})
    with pytest.raises(TimeWindowError, match="^capability is not currently valid$"):
        kernel.verifier.verify(future, request)
    expired = _rebuild(kernel, request, {"issued_at": now - 10, "expires_at": now - 1})
    with pytest.raises(TimeWindowError, match="^capability is not currently valid$"):
        kernel.verifier.verify(expired, request)


def test_verifier_rejects_stale_epoch(kernel_factory):
    kernel = kernel_factory()
    request = read_request()
    issued = kernel.authority.issue(request)
    assert kernel.state.bump_epoch(kernel.authority_key) == 2
    with pytest.raises(EpochError, match="^stale or invalid authorization epoch$"):
        kernel.verifier.verify(issued.envelope, request)


def test_verifier_rejects_unsupported_action(kernel_factory):
    kernel = kernel_factory()
    request = ActionRequest(
        "req-unsupported",
        "planner",
        "executor",
        "process.exec",
        "workspace/allowed.txt",
        {"command": "id"},
    )
    envelope = _rebuild(
        kernel,
        request,
        {},
        action="process.exec",
        binding={"path": request.resource, "whatever": 1},
    )
    with pytest.raises(ScopeError, match="^unsupported capability action$"):
        kernel.verifier.verify(envelope, request)


def test_verifier_default_ttl_and_skew(kernel_factory):
    kernel = kernel_factory()
    assert kernel.verifier.maximum_ttl_seconds == 300
    assert kernel.verifier.clock_skew_seconds == 5


def test_authority_rejects_invalid_issuer(kernel_factory):
    kernel = kernel_factory()
    with pytest.raises(ValueError, match="^invalid issuer$"):
        CapabilityAuthority(
            "",
            kernel.authority_key,
            kernel.state,
            kernel.guard,
            kernel.contexts,
            policy=kernel.authority.policy,
            clock=kernel.clock,
        )
    with pytest.raises(ValueError, match="^invalid issuer$"):
        CapabilityAuthority(
            "bad issuer!",
            kernel.authority_key,
            kernel.state,
            kernel.guard,
            kernel.contexts,
            policy=kernel.authority.policy,
            clock=kernel.clock,
        )


def test_authority_policy_validation_messages():
    with pytest.raises(ValueError, match="^invalid authority policy$"):
        AuthorityPolicy(policy_id="").validate()
    with pytest.raises(ValueError, match="^invalid authority policy$"):
        AuthorityPolicy(allowed_actions=frozenset()).validate()
    with pytest.raises(ValueError, match="^authority policy needs principals and audiences$"):
        AuthorityPolicy(allowed_principals=frozenset()).validate()
    with pytest.raises(ValueError, match="^authority policy needs principals and audiences$"):
        AuthorityPolicy(allowed_audiences=frozenset()).validate()
    with pytest.raises(ValueError, match="^authority policy needs resource prefixes$"):
        AuthorityPolicy(allowed_resource_prefixes=()).validate()
    with pytest.raises(ValueError, match="^invalid capability TTL policy$"):
        AuthorityPolicy(default_ttl_seconds=0).validate()
    with pytest.raises(ValueError, match="^invalid capability TTL policy$"):
        AuthorityPolicy(maximum_ttl_seconds=4000).validate()
    with pytest.raises(ValueError, match="^invalid capability TTL policy$"):
        AuthorityPolicy(default_ttl_seconds=301).validate()


def test_authority_policy_defaults_exact():
    policy = AuthorityPolicy()
    assert policy.policy_id == "mgk-authority-v1"
    assert policy.allowed_actions == frozenset({"resource.read", "resource.create"})
    assert policy.allowed_principals == frozenset({"planner"})
    assert policy.allowed_audiences == frozenset({"executor"})
    assert policy.allowed_resource_prefixes == ("workspace/",)
    assert policy.default_ttl_seconds == 60
    assert policy.maximum_ttl_seconds == 300


def test_authority_rejects_oversize_canonical_create(kernel_factory):
    kernel = kernel_factory()
    from mgk.crypto import b64u_encode
    from mgk.errors import CanonicalizationError

    oversized = b"x" * (256 * 1024)
    request = ActionRequest(
        "req-create-big",
        "planner",
        "executor",
        "resource.create",
        "workspace/big.txt",
        {"content_b64": b64u_encode(oversized)},
    )
    with pytest.raises(CanonicalizationError, match="^canonical document exceeds size limit$"):
        kernel.authority.issue(request)


def test_saxp_defaults_exact():
    evaluator = SAXPEvaluator()
    assert evaluator.policy_id == "saxp-level1-v1"
    assert evaluator.minimum_sentidino == 5000


def test_saxp_rejects_invalid_policy():
    with pytest.raises(ValueError, match="^invalid SAXP policy$"):
        SAXPEvaluator(policy_id="")
    with pytest.raises(ValueError, match="^invalid SAXP policy$"):
        SAXPEvaluator(minimum_sentidino="5000")
    with pytest.raises(ValueError, match="^minimum_sentidino outside 0..10000$"):
        SAXPEvaluator(minimum_sentidino=-1)
    with pytest.raises(ValueError, match="^minimum_sentidino outside 0..10000$"):
        SAXPEvaluator(minimum_sentidino=10001)


def test_saxp_custom_policy_is_bound_to_decision(kernel_factory):
    kernel = kernel_factory()
    request = read_request()
    evaluator = SAXPEvaluator(policy_id="policy-exact", minimum_sentidino=100)
    decision = evaluator.evaluate(request, SAFE_CONTEXT)
    payload = decision.to_payload()
    assert payload["policy_id"] == "policy-exact"
    assert payload["result"] == "TEN_XEITO"
    assert payload["reason_codes"] == ["COHERENCE_GATE_SATISFIED"]
    assert payload["request_digest"] == request.digest()


def test_cha_default_weights_exact():
    from mgk import CHAAdapter

    adapter = CHAAdapter()
    assert adapter.weights == (4000, 3000, 3000)