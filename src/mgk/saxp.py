"""Binding SAXP Level 1 evaluation."""

from __future__ import annotations

from enum import StrEnum

from .canonical import digest
from .errors import SchemaError
from .models import ActionRequest, SAXPContext, SAXPDecision


class SAXPResult(StrEnum):
    TEN_XEITO = "TEN_XEITO"
    REQUIRE_XEITO = "REQUIRE_XEITO"
    NON_TEN_XEITO = "NON_TEN_XEITO"


class SAXPEvaluator:
    """Deterministic evaluator. REQUIRE_XEITO never grants execution authority."""

    def __init__(self, policy_id: str = "saxp-level1-v1", minimum_sentidino: int = 5000):
        if not policy_id or type(minimum_sentidino) is not int:
            raise ValueError("invalid SAXP policy")
        if not 0 <= minimum_sentidino <= 10000:
            raise ValueError("minimum_sentidino outside 0..10000")
        self.policy_id = policy_id
        self.minimum_sentidino = minimum_sentidino

    @staticmethod
    def _validate_context(context: SAXPContext) -> None:
        integer_fields = (
            context.coherence_delta,
            context.systemic_pressure,
            context.threshold_k,
            context.sentidino,
        )
        if any(type(value) is not int for value in integer_fields):
            raise SchemaError("SAXP numeric inputs must be integers")
        if context.threshold_k < 0 or context.systemic_pressure < 0:
            raise SchemaError("SAXP pressure inputs must be non-negative")
        if not 0 <= context.sentidino <= 10000:
            raise SchemaError("sentidino outside 0..10000")
        boolean_fields = (
            context.information_complete,
            context.critical_uncertainty,
            context.control_risk,
            context.ethical_constraints_satisfied,
        )
        if any(type(value) is not bool for value in boolean_fields):
            raise SchemaError("SAXP flags must be booleans")

    def evaluate(self, request: ActionRequest, context: SAXPContext) -> SAXPDecision:
        self._validate_context(context)
        reasons: list[str] = []

        if context.control_risk:
            reasons.append("CONTROL_RISK")
        if not context.ethical_constraints_satisfied:
            reasons.append("ETHICAL_CONSTRAINT_FAILED")
        if context.coherence_delta < 0:
            reasons.append("COHERENCE_DECREASE")
        if context.systemic_pressure > context.threshold_k:
            reasons.append("THRESHOLD_K_EXCEEDED")

        if reasons:
            result = SAXPResult.NON_TEN_XEITO
        else:
            if context.critical_uncertainty:
                reasons.append("CRITICAL_UNCERTAINTY")
            if not context.information_complete:
                reasons.append("INFORMATION_INCOMPLETE")
            if context.sentidino < self.minimum_sentidino:
                reasons.append("SENTIDINO_RECALIBRATION_REQUIRED")
            result = SAXPResult.REQUIRE_XEITO if reasons else SAXPResult.TEN_XEITO

        if not reasons:
            reasons.append("COHERENCE_GATE_SATISFIED")
        return SAXPDecision(
            result=result.value,
            reason_codes=tuple(sorted(reasons)),
            request_digest=request.digest(),
            context_digest=digest(context.to_payload()),
            policy_id=self.policy_id,
        )
