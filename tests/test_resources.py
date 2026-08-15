import os
from dataclasses import replace

import pytest

from mgk import ActionRequest
from mgk.crypto import b64u_encode

from .helpers import read_request


def create_request(content=b"new content", resource="workspace/new.txt", request_id="create-1"):
    return ActionRequest(
        request_id=request_id,
        principal="planner",
        audience="executor",
        action="resource.create",
        resource=resource,
        parameters={"content_b64": b64u_encode(content)},
    )


def test_resource_change_after_authorization_is_denied(kernel_factory):
    kernel = kernel_factory()
    request = read_request()
    issued = kernel.authority.issue(request)
    (kernel.root / "resources/workspace/allowed.txt").write_bytes(b"substituted")
    result = kernel.executor.execute(issued.envelope, request)
    assert result.success is False
    assert result.execution_authority == 0
    assert result.reason_code == "RESOURCE_ERROR"


@pytest.mark.parametrize(
    "path",
    [
        "../outside.txt",
        "workspace/../../outside.txt",
        "/etc/passwd",
        "workspace\\..\\outside.txt",
        "workspace/./allowed.txt",
    ],
)
def test_path_traversal_is_denied(kernel_factory, path):
    kernel = kernel_factory()
    with pytest.raises(Exception):
        kernel.authority.issue(read_request(resource=path))


def test_final_symlink_is_denied(kernel_factory):
    kernel = kernel_factory()
    target = kernel.root / "outside.txt"
    target.write_bytes(b"secret")
    link = kernel.root / "resources/workspace/link.txt"
    link.symlink_to(target)
    with pytest.raises(Exception):
        kernel.authority.issue(read_request(resource="workspace/link.txt"))


def test_intermediate_symlink_is_denied(kernel_factory):
    kernel = kernel_factory()
    outside = kernel.root / "outside-dir"
    outside.mkdir()
    (outside / "file.txt").write_bytes(b"secret")
    (kernel.root / "resources/workspace/linkdir").symlink_to(outside, target_is_directory=True)
    with pytest.raises(Exception):
        kernel.authority.issue(read_request(resource="workspace/linkdir/file.txt"))


def test_bound_create_succeeds_once(kernel_factory):
    kernel = kernel_factory()
    request = create_request()
    issued = kernel.authority.issue(request)
    result = kernel.executor.execute(issued.envelope, request)
    assert result.success is True
    assert (kernel.root / "resources/workspace/new.txt").read_bytes() == b"new content"
    assert kernel.executor.execute(issued.envelope, request).success is False


def test_create_target_race_fails_closed(kernel_factory):
    kernel = kernel_factory()
    request = create_request()
    issued = kernel.authority.issue(request)
    target = kernel.root / "resources/workspace/new.txt"
    target.write_bytes(b"racer")
    result = kernel.executor.execute(issued.envelope, request)
    assert result.success is False
    assert target.read_bytes() == b"racer"


def test_create_content_mutation_fails_before_side_effect(kernel_factory):
    kernel = kernel_factory()
    original = create_request(b"authorized")
    issued = kernel.authority.issue(original)
    changed = replace(original, parameters={"content_b64": b64u_encode(b"attacker")})
    result = kernel.executor.execute(issued.envelope, changed)
    assert result.success is False
    assert not (kernel.root / "resources/workspace/new.txt").exists()
