from __future__ import annotations

import pytest

from mgk.crypto import b64u_encode
from mgk.errors import SchemaError
from mgk.models import ActionRequest

from .conftest import SAFE_CONTEXT


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


def test_write_file_non_string_content_exact_error(bundle):
    with pytest.raises(SchemaError, match="^sandbox.write_file requires canonical content_b64$"):
        bundle.authority.issue(
            make_request("sw1", "sandbox.write_file", "files/x.txt", {"content_b64": 123}),
            context=SAFE_CONTEXT,
        )


def test_append_file_non_string_content_exact_error(bundle):
    with pytest.raises(SchemaError, match="^sandbox.append_file requires canonical content_b64$"):
        bundle.authority.issue(
            make_request("sa1", "sandbox.append_file", "files/x.txt", {"content_b64": 123}),
            context=SAFE_CONTEXT,
        )


def test_create_record_non_string_content_exact_error(bundle):
    with pytest.raises(SchemaError, match="^sandbox.create_record requires canonical content_b64$"):
        bundle.authority.issue(
            make_request("sc1", "sandbox.create_record", "records/x", {"content_b64": 123}),
            context=SAFE_CONTEXT,
        )


def test_resource_create_non_string_content_exact_error(bundle):
    with pytest.raises(SchemaError, match="^resource.create requires canonical content_b64$"):
        bundle.authority.issue(
            make_request("rc1", "resource.create", "files/x.txt", {"content_b64": 123}),
            context=SAFE_CONTEXT,
        )


def test_write_file_missing_content_exact_error(bundle):
    with pytest.raises(SchemaError, match="^sandbox.write_file requires canonical content_b64$"):
        bundle.authority.issue(
            make_request("mw1", "sandbox.write_file", "files/x.txt", {"other": 1}),
            context=SAFE_CONTEXT,
        )


def test_read_actions_take_no_parameters_exact_error(bundle):
    for action, resource in (
        ("sandbox.read_file", "files/x.txt"),
        ("sandbox.read_record", "records/x"),
    ):
        with pytest.raises(SchemaError, match="^" + action + " takes no parameters$"):
            bundle.authority.issue(
                make_request("tp1", action, resource, {"extra": 1})
            )


def test_write_actions_reject_extra_parameters(bundle):
    for action, resource, message in (
        ("sandbox.write_file", "files/x.txt", "sandbox.write_file requires canonical content_b64"),
        ("sandbox.append_file", "files/x.txt", "sandbox.append_file requires canonical content_b64"),
        ("sandbox.create_record", "records/x", "sandbox.create_record requires canonical content_b64"),
        ("resource.create", "files/x.txt", "resource.create requires canonical content_b64"),
    ):
        with pytest.raises(SchemaError, match="^" + message + "$"):
            bundle.authority.issue(
                make_request("xp1", action, resource, {"content_b64": b64u_encode(b"x"), "extra": 1}),
                context=SAFE_CONTEXT,
            )


def test_sandbox_read_record_is_allowed_and_binds_present(bundle):
    (bundle.workspace.records_root / "rec").write_bytes(b'{"a": 1}')
    issued = bundle.authority.issue(make_request("rr1", "sandbox.read_record", "records/rec"))
    assert issued.envelope is not None
    assert issued.decision.result == "TEN_XEITO"
    from mgk.canonical import parse_canonical

    envelope = parse_canonical(issued.envelope)
    assert envelope["payload"]["resource_binding"]["state"] == "present"


def test_resource_create_issue_result_fields(bundle):
    issued = bundle.authority.issue(
        make_request("ci1", "resource.create", "files/new.txt", {"content_b64": b64u_encode(b"abc")}),
        context=SAFE_CONTEXT,
    )
    assert issued.envelope is not None
    assert issued.capability_id is not None
    assert issued.decision.result == "TEN_XEITO"


@pytest.mark.parametrize(
    "action,resource,payload",
    [
        ("sandbox.write_file", "files/out.txt", {"content_b64": b64u_encode(b"x")}),
        ("sandbox.append_file", "files/out.txt", {"content_b64": b64u_encode(b"x")}),
        ("sandbox.create_record", "records/rec", {"content_b64": b64u_encode(b'{"a": 1}')}),
    ],
)
def test_sandbox_actions_executor_output_is_none(bundle, action, resource, payload):
    if action == "sandbox.append_file":
        (bundle.workspace.files_root / "out.txt").write_bytes(b"base")
    req = make_request("ew1", action, resource, payload)
    issued = bundle.authority.issue(req, context=SAFE_CONTEXT)
    result = bundle.executor.execute(issued.envelope, req)
    assert result.success is True
    assert result.output is None
    assert result.output_digest is not None