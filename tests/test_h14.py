from dataclasses import replace

import pytest

from mgk import ActionRequest
from mgk.canonical import canonicalize, parse_canonical
from mgk.crypto import b64u_decode, b64u_encode

from .helpers import read_request


@pytest.mark.adversarial
def test_compromised_planner_cannot_get_forbidden_capability(kernel_factory):
    kernel = kernel_factory()
    attacks = [
        ActionRequest("h14-exec", "planner", "executor", "process.exec", "workspace/allowed.txt", {"command": "id"}),
        ActionRequest("h14-outside", "planner", "executor", "resource.read", "../outside.txt", {}),
        ActionRequest("h14-deputy", "planner", "admin-executor", "resource.read", "workspace/allowed.txt", {}),
        ActionRequest("h14-principal", "root", "executor", "resource.read", "workspace/allowed.txt", {}),
    ]
    issued = 0
    for attack in attacks:
        try:
            result = kernel.authority.issue(attack)
            issued += int(result.envelope is not None)
        except Exception:
            pass
    assert issued == 0


@pytest.mark.adversarial
def test_compromised_planner_cannot_forge_or_mutate(kernel_factory):
    kernel = kernel_factory()
    request = read_request()
    issued = kernel.authority.issue(request)
    document = parse_canonical(issued.envelope)
    raw = bytearray(b64u_decode(document["signature"]))
    raw[-1] ^= 0x80
    document["signature"] = b64u_encode(bytes(raw))
    forged = canonicalize(document)
    result = kernel.executor.execute(forged, request)
    assert result.execution_authority == 0

    altered = replace(request, resource="workspace/other.txt")
    result = kernel.executor.execute(issued.envelope, altered)
    assert result.execution_authority == 0


@pytest.mark.adversarial
def test_h14_forbidden_executions_remain_zero_across_attack_set(kernel_factory):
    kernel = kernel_factory()
    request = read_request()
    issued = kernel.authority.issue(request)
    attacks = []

    signature = parse_canonical(issued.envelope)
    signature["signature"] = b64u_encode(b"\x00" * 64)
    attacks.append((canonicalize(signature), request))

    payload = parse_canonical(issued.envelope)
    payload["payload"]["scope"]["action"] = "process.exec"
    attacks.append((canonicalize(payload), request))

    attacks.append((issued.envelope + b"\n", request))
    attacks.append((issued.envelope, replace(request, principal="attacker")))
    attacks.append((issued.envelope, replace(request, audience="other")))
    attacks.append((issued.envelope, replace(request, resource="workspace/substitute.txt")))

    forbidden_executions = 0
    for envelope, changed_request in attacks:
        result = kernel.executor.execute(envelope, changed_request)
        forbidden_executions += int(result.success)
    assert forbidden_executions == 0


@pytest.mark.adversarial
def test_exception_is_fail_closed(kernel_factory):
    kernel = kernel_factory()
    request = read_request()
    issued = kernel.authority.issue(request)
    kernel.guard.read_bound = lambda _binding: (_ for _ in ()).throw(RuntimeError("boom"))
    result = kernel.executor.execute(issued.envelope, request)
    assert result.success is False
    assert result.execution_authority == 0
    assert result.reason_code == "UNEXPECTED_EXCEPTION"
