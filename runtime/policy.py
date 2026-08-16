"""Runtime policy: maps proposals to SAXP context and enforces the closed action set."""

from __future__ import annotations

from dataclasses import dataclass, field

from mgk.authority import SANDBOX_ACTIONS
from mgk.models import ActionRequest, SAXPContext

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

REQUIRE_HUMAN_CONTEXT = SAXPContext(
    coherence_delta=100,
    systemic_pressure=10,
    threshold_k=100,
    sentidino=9000,
    information_complete=False,
    critical_uncertainty=True,
    control_risk=False,
    ethical_constraints_satisfied=True,
)

DENY_ALL_CONTEXT = SAXPContext(
    coherence_delta=100,
    systemic_pressure=10,
    threshold_k=100,
    sentidino=9000,
    information_complete=True,
    critical_uncertainty=False,
    control_risk=True,
    ethical_constraints_satisfied=True,
)


@dataclass(frozen=True)
class RuntimePolicy:
    mode: str = "allow_safe"
    allowed_actions: frozenset[str] = field(
        default_factory=lambda: frozenset(SANDBOX_ACTIONS)
        | frozenset({"resource.read", "resource.create"})
    )
    allowed_resource_prefixes: tuple[str, ...] = ("files/", "records/", "workspace/")
    sensitive_actions: frozenset[str] = field(
        default_factory=lambda: frozenset(
            {"sandbox.write_file", "sandbox.append_file", "sandbox.create_record"}
        )
    )

    def __post_init__(self) -> None:
        if self.mode not in {"allow_safe", "deny_all", "require_human"}:
            raise ValueError("invalid runtime policy mode")

    def allows(self, action: str, resource: str) -> bool:
        if action not in self.allowed_actions:
            return False
        return any(resource.startswith(prefix) for prefix in self.allowed_resource_prefixes)

    def context_for(self, request: ActionRequest) -> SAXPContext:
        if self.mode == "deny_all":
            return DENY_ALL_CONTEXT
        if self.mode == "require_human":
            return REQUIRE_HUMAN_CONTEXT
        if request.action not in self.allowed_actions:
            return DENY_ALL_CONTEXT
        if not any(
            request.resource.startswith(prefix) for prefix in self.allowed_resource_prefixes
        ):
            return DENY_ALL_CONTEXT
        if request.action in self.sensitive_actions:
            return REQUIRE_HUMAN_CONTEXT
        return SAFE_CONTEXT

    def resolved_context(self) -> SAXPContext:
        """Operator-resolved context used after human approval (TEN_XEITO eligible)."""
        return SAFE_CONTEXT