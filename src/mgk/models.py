"""Authority-bound MGK data structures."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from .canonical import digest


def _copy_mapping(value: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise TypeError("parameters must be a mapping")
    return dict(value)


@dataclass(frozen=True)
class ActionRequest:
    request_id: str
    principal: str
    audience: str
    action: str
    resource: str
    parameters: Mapping[str, Any]

    def to_payload(self) -> dict[str, Any]:
        return {
            "action": self.action,
            "audience": self.audience,
            "parameters": _copy_mapping(self.parameters),
            "principal": self.principal,
            "request_id": self.request_id,
            "resource": self.resource,
        }

    def digest(self) -> str:
        return digest(self.to_payload())


@dataclass(frozen=True)
class SAXPContext:
    coherence_delta: int
    systemic_pressure: int
    threshold_k: int
    sentidino: int
    information_complete: bool
    critical_uncertainty: bool
    control_risk: bool
    ethical_constraints_satisfied: bool

    def to_payload(self) -> dict[str, Any]:
        return {
            "coherence_delta": self.coherence_delta,
            "control_risk": self.control_risk,
            "critical_uncertainty": self.critical_uncertainty,
            "ethical_constraints_satisfied": self.ethical_constraints_satisfied,
            "information_complete": self.information_complete,
            "sentidino": self.sentidino,
            "systemic_pressure": self.systemic_pressure,
            "threshold_k": self.threshold_k,
        }


@dataclass(frozen=True)
class SAXPDecision:
    result: str
    reason_codes: tuple[str, ...]
    request_digest: str
    context_digest: str
    policy_id: str

    def to_payload(self) -> dict[str, Any]:
        return {
            "context_digest": self.context_digest,
            "policy_id": self.policy_id,
            "reason_codes": list(self.reason_codes),
            "request_digest": self.request_digest,
            "result": self.result,
        }


@dataclass(frozen=True)
class IssueResult:
    envelope: bytes | None
    decision: SAXPDecision
    capability_id: str | None


@dataclass(frozen=True)
class ExecutionResult:
    success: bool
    status: str
    reason_code: str
    execution_authority: int
    capability_id: str | None = None
    output_digest: str | None = None
    output: bytes | None = None
