from __future__ import annotations

import pytest

from mgk import ActionRequest, CapabilityVerifier, FixedClock
from mgk.canonical import digest, parse_canonical
from mgk.crypto import b64u_encode
from mgk.errors import ScopeError, TimeWindowError

from .conftest import SAFE_CONTEXT
from .helpers import read_request


@pytest.fixture
def bundle(tmp_path):
    from runtime.config import RuntimeConfig
    from runtime.workspace import Workspace

    config = RuntimeConfig.from_workdir(tmp_path / "rt")
    return Workspace(config).create_runtime()


def make_request(request_id, action, resource, parameters=None):
    return ActionRequest(
        request_id=request_id,
        principal="planner",
        audience="executor",
        action=action,
        resource=resource,
        parameters=parameters or {},
    )


def _reissued_payload(bundle, request, transform):
    issued = bundle.authority.issue(request, context=SAFE_CONTEXT)
    assert issued.envelope is not None
    payload = dict(parse_canonical(issued.envelope)["payload"])
    payload = transform(payload)
    base = {key: value for key, value in payload.items() if key != "capability_id"}
    payload["capability_id"] = digest(base)
    return payload


def test_validate_write_binding_rejects_wrong_keyset_exact(bundle):
    request = make_request("v1", "sandbox.write_file", "files/out.txt", {"content_b64": b64u_encode(b"x")})
    payload = _reissued_payload(
        bundle,
        request,
        lambda p: {**p, "resource_binding": {**p["resource_binding"], "extra": 1}},
    )
    with pytest.raises(ScopeError, match="^invalid write resource binding$"):
        bundle.verifier._validate_payload(payload, request)


def test_validate_write_binding_rejects_wrong_state_exact(bundle):
    request = make_request("v2", "sandbox.write_file", "files/out.txt", {"content_b64": b64u_encode(b"x")})
    payload = _reissued_payload(
        bundle,
        request,
        lambda p: {**p, "resource_binding": {**p["resource_binding"], "state": "append"}},
    )
    with pytest.raises(ScopeError, match="^invalid write resource binding$"):
        bundle.verifier._validate_payload(payload, request)


def test_validate_write_pre_state_rejects_bogus_exact(bundle):
    request = make_request("v3", "sandbox.write_file", "files/out.txt", {"content_b64": b64u_encode(b"x")})
    payload = _reissued_payload(
        bundle,
        request,
        lambda p: {**p, "resource_binding": {**p["resource_binding"], "pre_state": "bogus"}},
    )
    with pytest.raises(ScopeError, match="^invalid write pre-state$"):
        bundle.verifier._validate_payload(payload, request)


def test_validate_write_pre_state_present_succeeds(bundle):
    (bundle.workspace.files_root / "out.txt").write_bytes(b"existing")
    request = make_request("v4", "sandbox.write_file", "files/out.txt", {"content_b64": b64u_encode(b"x")})
    payload = _reissued_payload(bundle, request, lambda p: p)
    assert payload["resource_binding"]["pre_state"] == "present"
    assert bundle.verifier._validate_payload(payload, request) is payload


def test_validate_append_binding_rejects_wrong_keyset_exact(bundle):
    (bundle.workspace.files_root / "out.txt").write_bytes(b"base")
    request = make_request("v5", "sandbox.append_file", "files/out.txt", {"content_b64": b64u_encode(b"x")})
    payload = _reissued_payload(
        bundle,
        request,
        lambda p: {**p, "resource_binding": {**p["resource_binding"], "extra": 1}},
    )
    with pytest.raises(ScopeError, match="^invalid append resource binding$"):
        bundle.verifier._validate_payload(payload, request)


def test_validate_append_binding_rejects_wrong_state_exact(bundle):
    (bundle.workspace.files_root / "out.txt").write_bytes(b"base")
    request = make_request("v6", "sandbox.append_file", "files/out.txt", {"content_b64": b64u_encode(b"x")})
    payload = _reissued_payload(
        bundle,
        request,
        lambda p: {**p, "resource_binding": {**p["resource_binding"], "state": "write"}},
    )
    with pytest.raises(ScopeError, match="^invalid append resource binding$"):
        bundle.verifier._validate_payload(payload, request)


def test_validate_scope_wrong_keys_exact(bundle):
    request = make_request("v7", "sandbox.write_file", "files/out.txt", {"content_b64": b64u_encode(b"x")})
    payload = _reissued_payload(
        bundle,
        request,
        lambda p: {**p, "scope": {"action": "sandbox.write_file", "resourcce": "files/out.txt"}},
    )
    with pytest.raises(ScopeError, match="^invalid capability scope$"):
        bundle.verifier._validate_payload(payload, request)


def test_validate_read_record_valid_payload_succeeds(bundle):
    (bundle.workspace.records_root / "rec").write_bytes(b'{"a": 1}')
    request = make_request("v8", "sandbox.read_record", "records/rec")
    payload = _reissued_payload(bundle, request, lambda p: p)
    assert bundle.verifier._validate_payload(payload, request) is payload


def test_verify_accepts_clock_skew_boundary(kernel_factory):
    kernel = kernel_factory()
    request = read_request()
    issued = kernel.authority.issue(request)
    skewed = CapabilityVerifier(
        kernel.verifier.public_key,
        kernel.state,
        clock=FixedClock(kernel.clock.now() - 5),
    )
    payload = skewed.verify(issued.envelope, request)
    assert payload["capability_id"] == issued.capability_id