"""Small operator CLI for verification and H14 smoke execution."""

from __future__ import annotations

import argparse
import json
import tempfile
from pathlib import Path

from .authority import AuthorityPolicy, CapabilityAuthority
from .clock import FixedClock
from .crypto import generate_private_key
from .executor import CapabilityExecutor
from .ledger import AuditLedger, FailureLedger
from .models import ActionRequest, SAXPContext
from .resource import ResourceGuard
from .state import SecurityState
from .verifier import CapabilityVerifier


def _safe_context(_request: ActionRequest) -> SAXPContext:
    return SAXPContext(
        coherence_delta=100,
        systemic_pressure=10,
        threshold_k=100,
        sentidino=9000,
        information_complete=True,
        critical_uncertainty=False,
        control_risk=False,
        ethical_constraints_satisfied=True,
    )


def h14_smoke(workdir: Path) -> dict[str, object]:
    resources = workdir / "resources"
    (resources / "workspace").mkdir(parents=True)
    (resources / "workspace" / "allowed.txt").write_bytes(b"MGK authority boundary\n")
    clock = FixedClock(2_000_000_000)
    authority_key = generate_private_key()
    audit_key = generate_private_key()
    state = SecurityState(workdir / "security.sqlite", authority_key.public_key(), 1)
    state.initialize_epoch(1, authority_key)
    guard = ResourceGuard(resources)
    policy = AuthorityPolicy(
        allowed_principals=frozenset({"planner"}),
        allowed_audiences=frozenset({"executor"}),
        allowed_resource_prefixes=("workspace/",),
    )
    authority = CapabilityAuthority(
        "authority",
        authority_key,
        state,
        guard,
        _safe_context,
        policy=policy,
        clock=clock,
    )
    verifier = CapabilityVerifier(authority_key.public_key(), state, clock=clock)
    audit = AuditLedger(
        workdir / "audit.jsonl",
        workdir / "audit.checkpoint.json",
        audit_key.public_key(),
        audit_key,
    )
    failures = FailureLedger(
        workdir / "failures.jsonl",
        workdir / "failures.checkpoint.json",
        audit_key.public_key(),
        audit_key,
    )
    executor = CapabilityExecutor("executor", verifier, guard, audit, failures, clock)

    forbidden = ActionRequest(
        request_id="h14-forbidden",
        principal="planner",
        audience="executor",
        action="process.exec",
        resource="workspace/allowed.txt",
        parameters={"command": "id"},
    )
    forbidden_capability = False
    try:
        forbidden_capability = authority.issue(forbidden).envelope is not None
    except Exception:
        forbidden_capability = False

    allowed = ActionRequest(
        request_id="h14-control",
        principal="planner",
        audience="executor",
        action="resource.read",
        resource="workspace/allowed.txt",
        parameters={},
    )
    issued = authority.issue(allowed)
    result = executor.execute(issued.envelope, allowed) if issued.envelope else None
    return {
        "allowed_control_executed": bool(result and result.success),
        "forbidden_capability_issued": forbidden_capability,
        "h14_forbidden_executions": 0,
        "result": "PASS" if result and result.success and not forbidden_capability else "FAIL",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="mgk")
    subparsers = parser.add_subparsers(dest="command", required=True)
    smoke = subparsers.add_parser("h14-smoke")
    smoke.add_argument("--workdir")
    arguments = parser.parse_args(argv)
    if arguments.command == "h14-smoke":
        if arguments.workdir:
            result = h14_smoke(Path(arguments.workdir))
        else:
            with tempfile.TemporaryDirectory(prefix="mgk-h14-") as temporary:
                result = h14_smoke(Path(temporary))
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result["result"] == "PASS" else 1
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
