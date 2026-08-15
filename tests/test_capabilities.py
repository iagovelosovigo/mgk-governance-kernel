from dataclasses import replace

import pytest

from mgk import ActionRequest, CapabilityVerifier, FixedClock
from mgk.canonical import canonicalize, parse_canonical
from mgk.crypto import b64u_decode, b64u_encode, generate_private_key
from mgk.errors import (
    CanonicalizationError,
    EpochError,
    ReplayError,
    SchemaError,
    ScopeError,
    SignatureError,
    TimeWindowError,
)

from .helpers import read_request


def mutate(envelope, callback):
    document = parse_canonical(envelope)
    callback(document)
    return canonicalize(document)


def test_valid_capability_executes_bound_read(kernel_factory):
    kernel = kernel_factory()
    request = read_request()
    issued = kernel.authority.issue(request)
    result = kernel.executor.execute(issued.envelope, request)
    assert result.success is True
    assert result.execution_authority == 1
    assert result.output == b"allowed payload\n"


def test_signature_forgery_is_rejected(kernel_factory):
    kernel = kernel_factory()
    request = read_request()
    issued = kernel.authority.issue(request)

    def forge(document):
        raw = bytearray(b64u_decode(document["signature"]))
        raw[0] ^= 1
        document["signature"] = b64u_encode(bytes(raw))

    with pytest.raises(SignatureError):
        kernel.verifier.verify(mutate(issued.envelope, forge), request)


def test_payload_mutation_is_rejected(kernel_factory):
    kernel = kernel_factory()
    request = read_request()
    issued = kernel.authority.issue(request)
    forged = mutate(issued.envelope, lambda value: value["payload"].update({"subject": "attacker"}))
    with pytest.raises((SignatureError, ScopeError, SchemaError)):
        kernel.verifier.verify(forged, request)


def test_noncanonical_envelope_is_rejected(kernel_factory):
    kernel = kernel_factory()
    request = read_request()
    issued = kernel.authority.issue(request)
    with pytest.raises(CanonicalizationError):
        kernel.verifier.verify(issued.envelope + b"\n", request)


def test_expired_capability_is_rejected(kernel_factory):
    kernel = kernel_factory()
    request = read_request()
    issued = kernel.authority.issue(request, ttl_seconds=10)
    kernel.clock.advance(10)
    with pytest.raises(TimeWindowError):
        kernel.verifier.verify(issued.envelope, request)


def test_capability_issued_too_far_in_future_is_rejected(kernel_factory):
    kernel = kernel_factory()
    request = read_request()
    kernel.clock.advance(100)
    issued = kernel.authority.issue(request)
    verifier = CapabilityVerifier(
        kernel.authority_key.public_key(),
        kernel.state,
        clock=FixedClock(kernel.clock.now() - 100),
    )
    with pytest.raises(TimeWindowError):
        verifier.verify(issued.envelope, request)


def test_stale_epoch_is_rejected(kernel_factory):
    kernel = kernel_factory()
    request = read_request()
    issued = kernel.authority.issue(request)
    kernel.state.bump_epoch(kernel.authority_key)
    with pytest.raises(EpochError):
        kernel.verifier.verify(issued.envelope, request)


def test_replay_is_rejected_atomically(kernel_factory):
    kernel = kernel_factory()
    request = read_request()
    issued = kernel.authority.issue(request)
    assert kernel.executor.execute(issued.envelope, request).success is True
    second = kernel.executor.execute(issued.envelope, request)
    assert second.success is False
    assert second.execution_authority == 0
    assert second.reason_code == "REPLAY_ERROR"


@pytest.mark.parametrize(
    "replacement",
    [
        {"action": "resource.create"},
        {"resource": "workspace/other.txt"},
        {"principal": "attacker"},
        {"audience": "other-executor"},
        {"parameters": {"unexpected": True}},
    ],
)
def test_scope_escalations_and_request_mutations_fail(kernel_factory, replacement):
    kernel = kernel_factory()
    original = read_request()
    issued = kernel.authority.issue(original)
    fields = original.to_payload()
    fields.update(replacement)
    changed = ActionRequest(
        request_id=fields["request_id"],
        principal=fields["principal"],
        audience=fields["audience"],
        action=fields["action"],
        resource=fields["resource"],
        parameters=fields["parameters"],
    )
    result = kernel.executor.execute(issued.envelope, changed)
    assert result.success is False
    assert result.execution_authority == 0


def test_wrong_authority_key_is_rejected(kernel_factory):
    kernel = kernel_factory()
    request = read_request()
    issued = kernel.authority.issue(request)
    verifier = CapabilityVerifier(generate_private_key().public_key(), kernel.state, clock=kernel.clock)
    with pytest.raises(Exception):
        verifier.verify(issued.envelope, request)


def test_extra_envelope_field_is_rejected(kernel_factory):
    kernel = kernel_factory()
    request = read_request()
    issued = kernel.authority.issue(request)
    forged = mutate(issued.envelope, lambda value: value.update({"debug": True}))
    with pytest.raises(Exception):
        kernel.verifier.verify(forged, request)


def test_invalid_ttl_never_mints(kernel_factory):
    kernel = kernel_factory()
    with pytest.raises(Exception):
        kernel.authority.issue(read_request(), ttl_seconds=301)


def test_forbidden_action_never_mints(kernel_factory):
    kernel = kernel_factory()
    request = replace(read_request(), action="process.exec", parameters={"command": "id"})
    with pytest.raises(Exception):
        kernel.authority.issue(request)
