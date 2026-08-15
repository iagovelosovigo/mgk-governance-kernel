from __future__ import annotations

from dataclasses import dataclass

import pytest

from mgk import (
    AuditLedger,
    AuthorityPolicy,
    CapabilityAuthority,
    CapabilityExecutor,
    CapabilityVerifier,
    FailureLedger,
    FixedClock,
    ResourceGuard,
    SAXPContext,
    SecurityState,
)
from mgk.crypto import generate_private_key


SAFE_CONTEXT = SAXPContext(
    coherence_delta=100,
    systemic_pressure=10,
    threshold_k=100,
    sentidino=9000,
    information_complete=True,
    critical_uncertainty=False,
    control_risk=False,
    ethical_constraints_satisfied=True,
)


class ContextRegistry:
    def __init__(self):
        self.default = SAFE_CONTEXT
        self.values = {}

    def __call__(self, request):
        return self.values.get(request.request_id, self.default)


@dataclass
class Kernel:
    clock: FixedClock
    authority_key: object
    audit_key: object
    state: SecurityState
    guard: ResourceGuard
    contexts: ContextRegistry
    authority: CapabilityAuthority
    verifier: CapabilityVerifier
    audit: AuditLedger
    failures: FailureLedger
    executor: CapabilityExecutor
    root: object


@pytest.fixture
def kernel_factory(tmp_path):
    serial = {"value": 0}

    def factory(name="kernel", expected_epoch=1):
        serial["value"] += 1
        root = tmp_path / f"{name}-{serial['value']}"
        resources = root / "resources"
        (resources / "workspace").mkdir(parents=True)
        (resources / "workspace" / "allowed.txt").write_bytes(b"allowed payload\n")
        clock = FixedClock(2_000_000_000)
        authority_key = generate_private_key()
        audit_key = generate_private_key()
        state = SecurityState(root / "state.sqlite", authority_key.public_key(), expected_epoch)
        state.initialize_epoch(1, authority_key)
        guard = ResourceGuard(resources)
        contexts = ContextRegistry()
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
            contexts,
            policy=policy,
            clock=clock,
        )
        verifier = CapabilityVerifier(authority_key.public_key(), state, clock=clock)
        audit = AuditLedger(
            root / "audit.jsonl",
            root / "audit.checkpoint.json",
            audit_key.public_key(),
            audit_key,
        )
        failures = FailureLedger(
            root / "failures.jsonl",
            root / "failures.checkpoint.json",
            audit_key.public_key(),
            audit_key,
        )
        executor = CapabilityExecutor("executor", verifier, guard, audit, failures, clock)
        return Kernel(
            clock,
            authority_key,
            audit_key,
            state,
            guard,
            contexts,
            authority,
            verifier,
            audit,
            failures,
            executor,
            root,
        )

    return factory
