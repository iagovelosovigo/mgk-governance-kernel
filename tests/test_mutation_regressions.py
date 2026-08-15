"""Boundary regressions added from the first independent mutation campaign."""

from __future__ import annotations

from dataclasses import replace
import hashlib
import os

import pytest

from mgk import (
    ActionRequest,
    ArrowRoute,
    ArrowRouter,
    AuthorityPolicy,
    CHAAdapter,
    CHAInput,
    ResourceGuard,
    SAXPContext,
    SAXPEvaluator,
    SAXPResult,
    SecurityState,
)
from mgk.canonical import canonicalize, digest, parse_canonical
from mgk.crypto import b64u_encode, generate_private_key, key_id
from mgk.errors import (
    AuthorizationDenied,
    EpochError,
    ReplayError,
    ResourceError,
    SchemaError,
    SignatureError,
    ScopeError,
)
from mgk.resource import MAX_RESOURCE_BYTES

from .conftest import SAFE_CONTEXT
from .helpers import read_request


def _issued_payload(kernel, request=None):
    request = request or read_request()
    document = parse_canonical(kernel.authority.issue(request).envelope)
    return request, document["payload"]


def _rebind_capability_id(payload):
    rebound = dict(payload)
    base = dict(rebound)
    base.pop("capability_id")
    rebound["capability_id"] = digest(base)
    return rebound


@pytest.mark.parametrize("payload", [None, [], "payload", 1, True])
def test_verifier_payload_must_be_an_exact_dictionary(kernel_factory, payload):
    kernel = kernel_factory()
    with pytest.raises(SchemaError):
        kernel.verifier._validate_payload(payload, read_request())


def test_verifier_payload_keys_are_exact(kernel_factory):
    kernel = kernel_factory()
    request, payload = _issued_payload(kernel)
    for changed in (
        {key: value for key, value in payload.items() if key != "issuer"},
        payload | {"debug": True},
    ):
        with pytest.raises(SchemaError):
            kernel.verifier._validate_payload(changed, request)


@pytest.mark.parametrize(
    "field,value",
    [
        ("schema", "mgk-capability/v2"),
        ("issuer", ""),
        ("issuer", 1),
        ("subject", ""),
        ("audience", True),
        ("nonce", "0" * 31),
        ("nonce", "g" * 32),
        ("capability_id", "0" * 63),
        ("request_digest", "g" * 64),
    ],
)
def test_verifier_rejects_each_invalid_scalar_field(kernel_factory, field, value):
    kernel = kernel_factory()
    request, payload = _issued_payload(kernel)
    changed = dict(payload)
    changed[field] = value
    with pytest.raises(SchemaError):
        kernel.verifier._validate_payload(changed, request)


def test_verifier_rejects_oversized_identity(kernel_factory):
    kernel = kernel_factory()
    request, payload = _issued_payload(kernel)
    changed = dict(payload)
    changed["issuer"] = "x" * 4097
    with pytest.raises(SchemaError):
        kernel.verifier._validate_payload(changed, request)


def test_verifier_rejects_identifier_digest_mismatch(kernel_factory):
    kernel = kernel_factory()
    request, payload = _issued_payload(kernel)
    changed = dict(payload)
    changed["issuer"] = "other-authority"
    with pytest.raises(SchemaError, match="identifier mismatch"):
        kernel.verifier._validate_payload(changed, request)


@pytest.mark.parametrize(
    "field,value,error",
    [
        ("scope", [], ScopeError),
        ("scope", {"action": "resource.read"}, ScopeError),
        ("scope", {"action": "resource.create", "resource": "workspace/allowed.txt"}, ScopeError),
        ("subject", "other-planner", ScopeError),
        ("audience", "other-executor", ScopeError),
        ("request_digest", "0" * 64, ScopeError),
    ],
)
def test_verifier_scope_and_request_binding_are_exact(kernel_factory, field, value, error):
    kernel = kernel_factory()
    request, payload = _issued_payload(kernel)
    changed = dict(payload)
    changed[field] = value
    changed = _rebind_capability_id(changed)
    with pytest.raises(error):
        kernel.verifier._validate_payload(changed, request)


@pytest.mark.parametrize(
    "saxp",
    [
        [],
        {"result": "TEN_XEITO"},
        {
            "context_digest": "0" * 64,
            "policy_id": "saxp-level1-v1",
            "reason_codes": ["COHERENCE_GATE_SATISFIED"],
            "request_digest": "0" * 64,
            "result": "TEN_XEITO",
        },
        {
            "context_digest": "0" * 64,
            "policy_id": "saxp-level1-v1",
            "reason_codes": ["DENIED"],
            "request_digest": "",
            "result": "NON_TEN_XEITO",
        },
        {
            "context_digest": "0" * 64,
            "policy_id": "saxp-level1-v1",
            "reason_codes": [],
            "request_digest": "",
            "result": "TEN_XEITO",
        },
    ],
)
def test_verifier_rejects_unbound_or_non_authorizing_saxp(kernel_factory, saxp):
    kernel = kernel_factory()
    request, payload = _issued_payload(kernel)
    changed = dict(payload)
    changed["saxp"] = saxp
    changed = _rebind_capability_id(changed)
    with pytest.raises((SchemaError, ScopeError)):
        kernel.verifier._validate_payload(changed, request)


@pytest.mark.parametrize(
    "binding",
    [
        [],
        {"path": "workspace/other.txt"},
        {"path": "workspace/allowed.txt", "sha256": "0" * 64, "size": 16},
        {
            "path": "workspace/allowed.txt",
            "sha256": "0" * 64,
            "size": 16,
            "state": "absent",
        },
    ],
)
def test_verifier_rejects_invalid_read_binding_shapes(kernel_factory, binding):
    kernel = kernel_factory()
    request, payload = _issued_payload(kernel)
    changed = dict(payload)
    changed["resource_binding"] = binding
    changed = _rebind_capability_id(changed)
    with pytest.raises(ScopeError):
        kernel.verifier._validate_payload(changed, request)


def test_verifier_accepts_exact_create_binding(kernel_factory):
    kernel = kernel_factory()
    request = ActionRequest(
        "create-exact",
        "planner",
        "executor",
        "resource.create",
        "workspace/exact.txt",
        {"content_b64": b64u_encode(b"exact")},
    )
    _, payload = _issued_payload(kernel, request)
    assert kernel.verifier._validate_payload(payload, request) == payload
    for changed_binding in (
        payload["resource_binding"] | {"state": "present"},
        {key: value for key, value in payload["resource_binding"].items() if key != "post_size"},
    ):
        changed = dict(payload)
        changed["resource_binding"] = changed_binding
        changed = _rebind_capability_id(changed)
        with pytest.raises(ScopeError):
            kernel.verifier._validate_payload(changed, request)


@pytest.mark.parametrize(
    "field,value,error",
    [
        ("request_id", "", SchemaError),
        ("request_id", "bad id", SchemaError),
        ("principal", "intruder", AuthorizationDenied),
        ("audience", "other", AuthorizationDenied),
        ("action", "process.exec", AuthorizationDenied),
        ("resource", "outside/file.txt", AuthorizationDenied),
    ],
)
def test_authority_request_policy_boundaries(kernel_factory, field, value, error):
    kernel = kernel_factory()
    request = replace(read_request(), **{field: value})
    with pytest.raises(error):
        kernel.authority._validate_request(request)


def test_authority_binding_contracts_are_exact(kernel_factory):
    kernel = kernel_factory()
    read = read_request()
    assert kernel.authority._bind_resource(read) == kernel.guard.bind_present(read.resource)
    with pytest.raises(SchemaError):
        kernel.authority._bind_resource(replace(read, parameters={"extra": True}))

    create = ActionRequest(
        "create-binding",
        "planner",
        "executor",
        "resource.create",
        "workspace/bound.txt",
        {"content_b64": b64u_encode(b"bound")},
    )
    assert kernel.authority._bind_resource(create) == {
        "path": "workspace/bound.txt",
        "post_sha256": hashlib.sha256(b"bound").hexdigest(),
        "post_size": 5,
        "state": "absent",
    }
    for parameters in ({}, {"content_b64": 1}, {"content_b64": "!!!"}, {"content_b64": "AA", "x": 1}):
        with pytest.raises((SchemaError, SignatureError, ValueError)):
            kernel.authority._bind_resource(replace(create, parameters=parameters))


def test_authority_issue_exact_payload_and_ttl_boundaries(kernel_factory):
    kernel = kernel_factory()
    request = read_request()
    issued = kernel.authority.issue(request, ttl_seconds=1)
    envelope = parse_canonical(issued.envelope)
    payload = envelope["payload"]
    assert issued.capability_id == payload["capability_id"]
    assert payload["issued_at"] == kernel.clock.now()
    assert payload["expires_at"] == kernel.clock.now() + 1
    assert payload["authorization_epoch"] == 1
    assert payload["issuer"] == "authority"
    assert payload["subject"] == "planner"
    assert payload["audience"] == "executor"
    assert payload["scope"] == {"action": "resource.read", "resource": request.resource}
    assert envelope["algorithm"] == "Ed25519"
    assert envelope["key_id"] == key_id(kernel.authority_key.public_key())
    for ttl in (0, -1, 301, True, 1.5, "1"):
        with pytest.raises(AuthorizationDenied):
            kernel.authority.issue(request, ttl_seconds=ttl)


def test_authority_rejects_invalid_context_provider(kernel_factory):
    kernel = kernel_factory()
    kernel.authority.context_provider = lambda _request: {}
    with pytest.raises(SchemaError):
        kernel.authority.issue(read_request())


@pytest.mark.parametrize(
    "weights",
    [
        (),
        (1, 2),
        (1, 2, 3, 4),
        (4000, 3000, -1),
        (4000, 3000, True),
        (4000, 3000, 2999),
    ],
)
def test_cha_weight_contract_is_exact(weights):
    with pytest.raises(ValueError):
        CHAAdapter(weights)


def test_cha_exact_score_components_and_input_boundaries():
    request = read_request()
    proposal = CHAAdapter((4000, 3000, 3000)).propose(
        request,
        CHAInput(9000, 6000, 3000, 2000, 8000),
    )
    assert proposal.request is request
    assert proposal.score == 4200
    assert proposal.intelligence_only is True
    assert proposal.components == {
        "cognitive_coherence": 3000,
        "dissonance": 2000,
        "experience": 8000,
        "integrated": 6000,
        "limbic_resonance": 6000,
        "reptile_integrity": 9000,
    }
    for field in CHAInput.__dataclass_fields__:
        for invalid in (-1, 10001, True, 1.5, "1"):
            values = {
                "reptile_integrity": 1,
                "limbic_resonance": 2,
                "cognitive_coherence": 3,
                "dissonance": 4,
                "experience": 5,
            }
            values[field] = invalid
            with pytest.raises(ValueError):
                CHAAdapter().propose(request, CHAInput(**values))


def test_arrow_validates_every_field_and_all_tie_breakers():
    router = ArrowRouter()
    valid = ArrowRoute("route", 0, 0, 0, 0)
    assert router.select([valid]) == valid
    assert router.select([]) is None
    invalid_routes = [
        replace(valid, route_id=""),
        replace(valid, coherence_delta=True),
        replace(valid, entropic_resistance=-1),
        replace(valid, systemic_pressure=-1),
        replace(valid, threshold_k=-1),
    ]
    for route in invalid_routes:
        with pytest.raises(ValueError):
            router.select([route])
    routes = [
        ArrowRoute("z", 5, 10, 8, 8),
        ArrowRoute("d", 5, 1, 8, 8),
        ArrowRoute("c", 6, 1, 8, 8),
        ArrowRoute("b", 6, 1, 7, 8),
        ArrowRoute("a", 6, 1, 7, 8),
    ]
    assert router.select(routes).route_id == "a"


@pytest.mark.parametrize(
    "field,value",
    [
        ("coherence_delta", True),
        ("systemic_pressure", -1),
        ("threshold_k", -1),
        ("sentidino", -1),
        ("sentidino", 10001),
        ("information_complete", 1),
        ("critical_uncertainty", 0),
        ("control_risk", "false"),
        ("ethical_constraints_satisfied", None),
    ],
)
def test_saxp_rejects_each_invalid_context_field(field, value):
    with pytest.raises(SchemaError):
        SAXPEvaluator().evaluate(read_request(), replace(SAFE_CONTEXT, **{field: value}))


def test_saxp_exact_combined_reasons_and_bindings():
    evaluator = SAXPEvaluator(policy_id="policy-exact", minimum_sentidino=5000)
    request = read_request()
    context = SAXPContext(
        coherence_delta=-1,
        systemic_pressure=11,
        threshold_k=10,
        sentidino=1,
        information_complete=False,
        critical_uncertainty=True,
        control_risk=True,
        ethical_constraints_satisfied=False,
    )
    decision = evaluator.evaluate(request, context)
    assert decision.result == SAXPResult.NON_TEN_XEITO
    assert decision.reason_codes == (
        "COHERENCE_DECREASE",
        "CONTROL_RISK",
        "ETHICAL_CONSTRAINT_FAILED",
        "THRESHOLD_K_EXCEEDED",
    )
    assert decision.request_digest == request.digest()
    assert decision.context_digest == digest(context.to_payload())
    assert decision.policy_id == "policy-exact"
    ten = evaluator.evaluate(request, SAFE_CONTEXT)
    assert ten.reason_codes == ("COHERENCE_GATE_SATISFIED",)


@pytest.mark.parametrize(
    "path",
    [
        "",
        ".",
        "..",
        "workspace/",
        "workspace//file",
        "workspace/../file",
        "workspace/./file",
        "/absolute",
        "workspace\\file",
        "workspace/\x00file",
        1,
        True,
    ],
)
def test_resource_parts_reject_all_nonportable_forms(path):
    with pytest.raises(ResourceError):
        ResourceGuard._parts(path)
    assert ResourceGuard._parts("workspace/file.txt") == ("workspace", "file.txt")


def test_resource_parts_depth_and_length_limits():
    with pytest.raises(ResourceError):
        ResourceGuard._parts("/".join(["x"] * 33))
    with pytest.raises(ResourceError):
        ResourceGuard._parts("x" * 4097)


def test_bind_absent_exact_boundaries(kernel_factory):
    kernel = kernel_factory()
    digest_hex = hashlib.sha256(b"").hexdigest()
    assert kernel.guard.bind_absent("workspace/empty.txt", digest_hex, 0) == {
        "path": "workspace/empty.txt",
        "post_sha256": digest_hex,
        "post_size": 0,
        "state": "absent",
    }
    for bad_hash, bad_size in (
        ("x" * 64, 0),
        ("0" * 63, 0),
        (digest_hex, True),
        (digest_hex, -1),
        (digest_hex, MAX_RESOURCE_BYTES + 1),
    ):
        with pytest.raises(ResourceError):
            kernel.guard.bind_absent("workspace/new.txt", bad_hash, bad_size)
    with pytest.raises(ResourceError):
        kernel.guard.bind_absent("workspace/allowed.txt", digest_hex, 0)


def test_read_bound_validates_shape_size_and_hash(kernel_factory):
    kernel = kernel_factory()
    binding = kernel.guard.bind_present("workspace/allowed.txt")
    assert kernel.guard.read_bound(binding) == b"allowed payload\n"
    invalid = [
        binding | {"state": "absent"},
        {key: value for key, value in binding.items() if key != "size"},
        binding | {"size": binding["size"] + 1},
        binding | {"sha256": "0" * 64},
    ]
    for changed in invalid:
        with pytest.raises(ResourceError):
            kernel.guard.read_bound(changed)


def test_create_bound_validates_every_precondition_and_remove(kernel_factory):
    kernel = kernel_factory()
    data = b"created"
    binding = kernel.guard.bind_absent(
        "workspace/created.txt",
        hashlib.sha256(data).hexdigest(),
        len(data),
    )
    for changed, changed_data in (
        ({key: value for key, value in binding.items() if key != "post_size"}, data),
        (binding | {"state": "present"}, data),
        (binding, bytearray(data)),
        (binding | {"post_size": len(data) + 1}, data),
        (binding | {"post_sha256": "0" * 64}, data),
    ):
        with pytest.raises(ResourceError):
            kernel.guard.create_bound(changed, changed_data)
    created_digest = kernel.guard.create_bound(binding, data)
    assert created_digest == hashlib.sha256(data).hexdigest()
    assert kernel.guard.remove_created(binding | {"state": "present"}, created_digest) is False
    assert kernel.guard.remove_created(binding, "0" * 64) is False
    assert kernel.guard.remove_created(binding, created_digest) is True
    assert not (kernel.root / "resources/workspace/created.txt").exists()
    assert kernel.guard.remove_created(binding, created_digest) is False


def test_resource_open_file_rejects_missing_directory_and_oversize(kernel_factory):
    kernel = kernel_factory()
    with pytest.raises(ResourceError):
        kernel.guard._open_file("workspace/missing.txt")
    with pytest.raises(ResourceError):
        kernel.guard._open_file("workspace")
    oversize = kernel.root / "resources/workspace/oversize.bin"
    with oversize.open("wb") as stream:
        stream.truncate(MAX_RESOURCE_BYTES + 1)
    with pytest.raises(ResourceError):
        kernel.guard._open_file("workspace/oversize.bin")


@pytest.mark.parametrize("minimum", [0, -1, True, 1.5, "1"])
def test_security_state_minimum_epoch_contract(tmp_path, minimum):
    key = generate_private_key()
    with pytest.raises(ValueError):
        SecurityState(tmp_path / "bad.sqlite", key.public_key(), minimum)


def test_security_state_epoch_and_nonce_boundaries(kernel_factory, tmp_path):
    kernel = kernel_factory()
    assert kernel.state.current_epoch() == 1
    assert kernel.state.nonce_count() == 0
    for nonce, capability_id, consumed_at in (
        (1, "id", 1),
        ("nonce", 1, 1),
        ("nonce", "id", True),
    ):
        with pytest.raises(ReplayError):
            kernel.state.consume_nonce(nonce, capability_id, consumed_at)
    kernel.state.consume_nonce("nonce", "capability", 10)
    assert kernel.state.nonce_count() == 1
    with pytest.raises(ReplayError):
        kernel.state.consume_nonce("nonce", "capability", 11)
    assert kernel.state.bump_epoch(kernel.authority_key) == 2
    assert kernel.state.current_epoch() == 2

    key = generate_private_key()
    empty = SecurityState(tmp_path / "empty.sqlite", key.public_key())
    with pytest.raises(EpochError):
        empty.current_epoch()
    for epoch in (0, -1, True, "1"):
        with pytest.raises(ValueError):
            empty.initialize_epoch(epoch, key)


def test_security_state_decode_rejects_each_invalid_envelope(kernel_factory):
    kernel = kernel_factory()
    wrong_key = generate_private_key()
    valid_document = {
        "epoch": 1,
        "key_id": key_id(kernel.authority_key.public_key()),
        "schema": "mgk-epoch/v1",
    }
    invalid_values = [
        [],
        {"document": valid_document},
        {"document": [], "signature": "x"},
        {"document": {"epoch": 1, "schema": "mgk-epoch/v1"}, "signature": "x"},
        {
            "document": valid_document | {"schema": "mgk-epoch/v2"},
            "signature": "x",
        },
        {
            "document": valid_document | {"key_id": key_id(wrong_key.public_key())},
            "signature": "x",
        },
    ]
    for value in invalid_values:
        with pytest.raises((EpochError, SchemaError, SignatureError)):
            kernel.state._decode_epoch(canonicalize(value))


def _assert_error(error_type, message, callback):
    with pytest.raises(error_type) as captured:
        callback()
    assert str(captured.value) == message


def test_verifier_reports_each_fail_closed_reason_exactly(kernel_factory):
    kernel = kernel_factory()
    request, payload = _issued_payload(kernel)

    _assert_error(
        SchemaError,
        "invalid capability payload schema",
        lambda: kernel.verifier._validate_payload(None, request),
    )
    _assert_error(
        SchemaError,
        "unsupported capability schema",
        lambda: kernel.verifier._validate_payload(
            _rebind_capability_id(payload | {"schema": "mgk-capability/v2"}),
            request,
        ),
    )
    for field in ("issuer", "subject", "audience", "capability_id", "request_digest", "nonce"):
        changed = dict(payload)
        changed[field] = ""
        _assert_error(
            SchemaError,
            f"invalid {field}",
            lambda changed=changed: kernel.verifier._validate_payload(changed, request),
        )
    _assert_error(
        SchemaError,
        "invalid nonce",
        lambda: kernel.verifier._validate_payload(payload | {"nonce": "g" * 32}, request),
    )
    _assert_error(
        SchemaError,
        "invalid capability digest",
        lambda: kernel.verifier._validate_payload(payload | {"request_digest": "g" * 64}, request),
    )
    _assert_error(
        SchemaError,
        "capability identifier mismatch",
        lambda: kernel.verifier._validate_payload(payload | {"issuer": "changed"}, request),
    )

    changed = _rebind_capability_id(payload | {"scope": []})
    _assert_error(
        ScopeError,
        "invalid capability scope",
        lambda: kernel.verifier._validate_payload(changed, request),
    )
    changed = _rebind_capability_id(
        payload | {"scope": {"action": "resource.read", "resource": "workspace/other.txt"}}
    )
    _assert_error(
        ScopeError,
        "capability scope does not match execution request",
        lambda: kernel.verifier._validate_payload(changed, request),
    )
    changed = _rebind_capability_id(payload | {"subject": "changed"})
    _assert_error(
        ScopeError,
        "subject or audience mismatch",
        lambda: kernel.verifier._validate_payload(changed, request),
    )
    changed = _rebind_capability_id(payload | {"request_digest": "0" * 64})
    _assert_error(
        ScopeError,
        "request payload mutation detected",
        lambda: kernel.verifier._validate_payload(changed, request),
    )

    changed = _rebind_capability_id(payload | {"saxp": []})
    _assert_error(
        SchemaError,
        "invalid SAXP evidence",
        lambda: kernel.verifier._validate_payload(changed, request),
    )
    saxp = dict(payload["saxp"])
    saxp["result"] = "REQUIRE_XEITO"
    changed = _rebind_capability_id(payload | {"saxp": saxp})
    _assert_error(
        ScopeError,
        "capability lacks TEN_XEITO",
        lambda: kernel.verifier._validate_payload(changed, request),
    )
    saxp = dict(payload["saxp"])
    saxp["request_digest"] = "0" * 64
    changed = _rebind_capability_id(payload | {"saxp": saxp})
    _assert_error(
        ScopeError,
        "SAXP evidence is not bound to the request",
        lambda: kernel.verifier._validate_payload(changed, request),
    )
    saxp = dict(payload["saxp"])
    saxp["reason_codes"] = []
    changed = _rebind_capability_id(payload | {"saxp": saxp})
    _assert_error(
        SchemaError,
        "invalid SAXP reason evidence",
        lambda: kernel.verifier._validate_payload(changed, request),
    )

    changed = _rebind_capability_id(payload | {"resource_binding": []})
    _assert_error(
        ScopeError,
        "resource binding mismatch",
        lambda: kernel.verifier._validate_payload(changed, request),
    )
    changed = _rebind_capability_id(
        payload | {"resource_binding": payload["resource_binding"] | {"state": "absent"}}
    )
    _assert_error(
        ScopeError,
        "invalid read resource binding",
        lambda: kernel.verifier._validate_payload(changed, request),
    )

    create = ActionRequest(
        "message-create",
        "planner",
        "executor",
        "resource.create",
        "workspace/message.txt",
        {"content_b64": b64u_encode(b"message")},
    )
    _, create_payload = _issued_payload(kernel, create)
    changed = _rebind_capability_id(
        create_payload
        | {"resource_binding": create_payload["resource_binding"] | {"state": "present"}}
    )
    _assert_error(
        ScopeError,
        "invalid create resource binding",
        lambda: kernel.verifier._validate_payload(changed, create),
    )


def test_authority_reports_each_policy_reason_exactly(kernel_factory):
    kernel = kernel_factory()
    _assert_error(
        SchemaError,
        "invalid request identifier",
        lambda: kernel.authority._validate_request(replace(read_request(), request_id="bad id")),
    )
    _assert_error(
        AuthorizationDenied,
        "action is outside authority policy",
        lambda: kernel.authority._validate_request(replace(read_request(), action="process.exec")),
    )
    _assert_error(
        AuthorizationDenied,
        "principal is outside authority policy",
        lambda: kernel.authority._validate_request(replace(read_request(), principal="intruder")),
    )
    _assert_error(
        AuthorizationDenied,
        "audience is outside authority policy",
        lambda: kernel.authority._validate_request(replace(read_request(), audience="other")),
    )
    _assert_error(
        AuthorizationDenied,
        "resource is outside authority policy",
        lambda: kernel.authority._validate_request(replace(read_request(), resource="outside.txt")),
    )
    _assert_error(
        SchemaError,
        "resource.read takes no parameters",
        lambda: kernel.authority._bind_resource(replace(read_request(), parameters={"x": 1})),
    )
    create = ActionRequest(
        "message-create",
        "planner",
        "executor",
        "resource.create",
        "workspace/message.txt",
        {},
    )
    _assert_error(
        SchemaError,
        "resource.create requires canonical content_b64",
        lambda: kernel.authority._bind_resource(create),
    )
    _assert_error(
        AuthorizationDenied,
        "unsupported action",
        lambda: kernel.authority._bind_resource(replace(read_request(), action="other")),
    )
    kernel.authority.context_provider = lambda _request: None
    _assert_error(
        SchemaError,
        "trusted context provider returned an invalid context",
        lambda: kernel.authority.issue(read_request()),
    )
    kernel.authority.context_provider = kernel.contexts
    _assert_error(
        AuthorizationDenied,
        "capability TTL exceeds authority policy",
        lambda: kernel.authority.issue(read_request(), ttl_seconds=0),
    )


def test_decision_helpers_report_validation_reasons_exactly():
    _assert_error(
        ValueError,
        "invalid CHA weights",
        lambda: CHAAdapter((1, 2)),
    )
    _assert_error(
        ValueError,
        "CHA weights must total 10000",
        lambda: CHAAdapter((4000, 3000, 2999)),
    )
    _assert_error(
        ValueError,
        "CHA inputs must be integer basis points",
        lambda: CHAAdapter().propose(read_request(), CHAInput(-1, 0, 0, 0, 0)),
    )
    _assert_error(
        ValueError,
        "invalid Arrow route",
        lambda: ArrowRouter().select([ArrowRoute("", 0, 0, 0, 0)]),
    )
    _assert_error(
        ValueError,
        "Arrow pressure values must be non-negative",
        lambda: ArrowRouter().select([ArrowRoute("route", 0, -1, 0, 0)]),
    )
    _assert_error(
        SchemaError,
        "SAXP numeric inputs must be integers",
        lambda: SAXPEvaluator().evaluate(
            read_request(), replace(SAFE_CONTEXT, coherence_delta=True)
        ),
    )
    _assert_error(
        SchemaError,
        "SAXP pressure inputs must be non-negative",
        lambda: SAXPEvaluator().evaluate(
            read_request(), replace(SAFE_CONTEXT, systemic_pressure=-1)
        ),
    )
    _assert_error(
        SchemaError,
        "sentidino outside 0..10000",
        lambda: SAXPEvaluator().evaluate(read_request(), replace(SAFE_CONTEXT, sentidino=-1)),
    )
    _assert_error(
        SchemaError,
        "SAXP flags must be booleans",
        lambda: SAXPEvaluator().evaluate(
            read_request(), replace(SAFE_CONTEXT, information_complete=1)
        ),
    )


def test_resource_guard_reports_every_binding_failure_exactly(kernel_factory):
    kernel = kernel_factory()
    _assert_error(
        ResourceError,
        "invalid resource path",
        lambda: ResourceGuard._parts(""),
    )
    _assert_error(
        ResourceError,
        "non-portable resource path",
        lambda: ResourceGuard._parts("workspace\\file"),
    )
    _assert_error(
        ResourceError,
        "path traversal is forbidden",
        lambda: ResourceGuard._parts("workspace/../file"),
    )
    _assert_error(
        ResourceError,
        "resource path is too deep",
        lambda: ResourceGuard._parts("/".join(["x"] * 33)),
    )
    _assert_error(
        ResourceError,
        "invalid post-state binding",
        lambda: kernel.guard.bind_absent("workspace/new.txt", "x" * 64, 0),
    )
    _assert_error(
        ResourceError,
        "invalid post-state size",
        lambda: kernel.guard.bind_absent(
            "workspace/new.txt", hashlib.sha256(b"").hexdigest(), -1
        ),
    )
    _assert_error(
        ResourceError,
        "create target already exists",
        lambda: kernel.guard.bind_absent(
            "workspace/allowed.txt", hashlib.sha256(b"").hexdigest(), 0
        ),
    )
    binding = kernel.guard.bind_present("workspace/allowed.txt")
    _assert_error(
        ResourceError,
        "invalid present-resource binding",
        lambda: kernel.guard.read_bound(binding | {"state": "absent"}),
    )
    _assert_error(
        ResourceError,
        "resource changed after authorization",
        lambda: kernel.guard.read_bound(binding | {"size": binding["size"] + 1}),
    )
    data = b"created"
    create_binding = kernel.guard.bind_absent(
        "workspace/created-message.txt",
        hashlib.sha256(data).hexdigest(),
        len(data),
    )
    _assert_error(
        ResourceError,
        "invalid absent-resource binding",
        lambda: kernel.guard.create_bound(
            {key: value for key, value in create_binding.items() if key != "post_size"},
            data,
        ),
    )
    _assert_error(
        ResourceError,
        "invalid create request",
        lambda: kernel.guard.create_bound(create_binding | {"state": "present"}, data),
    )
    _assert_error(
        ResourceError,
        "create payload does not match capability binding",
        lambda: kernel.guard.create_bound(create_binding, b"other"),
    )
    _assert_error(
        ResourceError,
        "cannot open bound resource: No such file or directory",
        lambda: kernel.guard._open_file("workspace/missing.txt"),
    )
    _assert_error(
        ResourceError,
        "bound resource is not a regular file",
        lambda: kernel.guard._open_file("workspace"),
    )
    oversize = kernel.root / "resources/workspace/message-oversize.bin"
    with oversize.open("wb") as stream:
        stream.truncate(MAX_RESOURCE_BYTES + 1)
    _assert_error(
        ResourceError,
        "bound resource exceeds size limit",
        lambda: kernel.guard._open_file("workspace/message-oversize.bin"),
    )


def test_security_state_reports_epoch_and_replay_failures_exactly(kernel_factory, tmp_path):
    kernel = kernel_factory()
    _assert_error(
        ReplayError,
        "invalid nonce consumption request",
        lambda: kernel.state.consume_nonce(1, "capability", 1),
    )
    kernel.state.consume_nonce("nonce-message", "capability", 1)
    _assert_error(
        ReplayError,
        "nonce was already consumed",
        lambda: kernel.state.consume_nonce("nonce-message", "capability", 2),
    )
    key = generate_private_key()
    empty = SecurityState(tmp_path / "message-empty.sqlite", key.public_key())
    _assert_error(
        EpochError,
        "authorization epoch is not initialized",
        empty.current_epoch,
    )
    _assert_error(
        EpochError,
        "invalid epoch envelope",
        lambda: kernel.state._decode_epoch(canonicalize([])),
    )
    _assert_error(
        EpochError,
        "invalid epoch document",
        lambda: kernel.state._decode_epoch(canonicalize({"document": [], "signature": "x"})),
    )
    document = {
        "epoch": 1,
        "key_id": key_id(kernel.authority_key.public_key()),
        "schema": "wrong",
    }
    _assert_error(
        EpochError,
        "unsupported epoch schema",
        lambda: kernel.state._decode_epoch(
            canonicalize({"document": document, "signature": "x"})
        ),
    )
    document = {
        "epoch": 1,
        "key_id": key_id(generate_private_key().public_key()),
        "schema": "mgk-epoch/v1",
    }
    _assert_error(
        EpochError,
        "epoch signer mismatch",
        lambda: kernel.state._decode_epoch(
            canonicalize({"document": document, "signature": "x"})
        ),
    )
