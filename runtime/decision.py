"""Decision pipeline: proposal -> SAXP -> ALLOW/DENY/REQUIRE_HUMAN/INDETERMINATE.

Central invariant: PROPOSAL IS NOT AUTHORITY. A proposal is data-only; no
governed side effect happens without a valid, scoped, single-use capability
issued by the kernel authority and executed by the kernel executor.
"""

from __future__ import annotations

import secrets
from enum import StrEnum
from typing import Any

from mgk.authority import CapabilityAuthority
from mgk.clock import SystemClock
from mgk.crypto import HUMAN_GATE_DOMAIN, sign
from mgk.errors import MGKError
from mgk.executor import CapabilityExecutor
from mgk.models import ActionRequest
from mgk.saxp import SAXPEvaluator, SAXPResult
from mgk.verifier import CapabilityVerifier

from .flight import FlightRecorder
from .policy import RuntimePolicy
from .runtime_ledger import RuntimeLedger


class DecisionState(StrEnum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    REQUIRE_HUMAN = "REQUIRE_HUMAN"
    INDETERMINATE = "INDETERMINATE"


class Decision:
    def __init__(
        self,
        state: DecisionState,
        request: dict[str, Any],
        request_digest: str,
        reason_codes: list[str],
        capability_id: str | None = None,
        executed: bool = False,
        output_digest: str | None = None,
        flight_hash: str | None = None,
        human_decision: str | None = None,
        human_signature: str | None = None,
        operator: str | None = None,
    ):
        self.state = state
        self.request = request
        self.request_digest = request_digest
        self.reason_codes = reason_codes
        self.capability_id = capability_id
        self.executed = executed
        self.output_digest = output_digest
        self.flight_hash = flight_hash
        self.human_decision = human_decision
        self.human_signature = human_signature
        self.operator = operator

    def to_dict(self) -> dict[str, Any]:
        return {
            "state": self.state.value,
            "request": self.request,
            "request_digest": self.request_digest,
            "reason_codes": self.reason_codes,
            "capability_id": self.capability_id,
            "executed": self.executed,
            "output_digest": self.output_digest,
            "flight_hash": self.flight_hash,
            "human_decision": self.human_decision,
            "human_signature": self.human_signature,
            "operator": self.operator,
        }


class DecisionPipeline:
    def __init__(
        self,
        authority: CapabilityAuthority,
        verifier: CapabilityVerifier,
        executor: CapabilityExecutor,
        policy: RuntimePolicy,
        flight: FlightRecorder,
        ledger: RuntimeLedger,
        operator_key: Any | None = None,
        clock: Any | None = None,
    ):
        self.authority = authority
        self.verifier = verifier
        self.executor = executor
        self.policy = policy
        self.flight = flight
        self.ledger = ledger
        self.operator_key = operator_key
        self.clock = clock or SystemClock()
        self.saxp = SAXPEvaluator()

    def _flight(self, event_type: str, data: dict[str, Any]) -> str:
        return self.flight.append(event_type, data, self.clock.now())

    def _request(self, request: dict[str, Any]) -> ActionRequest:
        return ActionRequest(
            request_id=str(request["request_id"]),
            principal=str(request["principal"]),
            audience=str(request["audience"]),
            action=str(request["action"]),
            resource=str(request["resource"]),
            parameters=dict(request["parameters"]),
        )

    def _record(self, request: ActionRequest, state: DecisionState, reason_codes: list[str]) -> None:
        now = self.clock.now()
        payload = request.to_payload()
        self.ledger.store_proposal(payload, request.digest(), now)

    def propose(self, request: dict[str, Any]) -> Decision:
        request_id = str(request["request_id"])
        try:
            bound = self._request(request)
        except (KeyError, TypeError, ValueError) as exc:
            return self._indeterminate(request_id, exc, request)
        try:
            self._record(bound, DecisionState.INDETERMINATE, [])
            context = self.policy.context_for(bound)
            decision = self.saxp.evaluate(bound, context)
            codes = list(decision.reason_codes)
            result = decision.result

            if result == SAXPResult.NON_TEN_XEITO.value:
                flight_hash = self._flight(
                    "DECISION_DENY",
                    {"request_id": bound.request_id, "reason_codes": codes},
                )
                now = self.clock.now()
                self.ledger.store_decision(
                    request_id,
                    bound.request_id,
                    DecisionState.DENY.value,
                    codes,
                    None,
                    False,
                    None,
                    flight_hash,
                    now,
                )
                return Decision(
                    DecisionState.DENY, bound.to_payload(), bound.digest(), codes, flight_hash=flight_hash
                )

            if result == SAXPResult.REQUIRE_XEITO.value:
                flight_hash = self._flight(
                    "DECISION_REQUIRE_HUMAN",
                    {"request_id": bound.request_id, "reason_codes": codes},
                )
                now = self.clock.now()
                self.ledger.store_decision(
                    request_id,
                    bound.request_id,
                    DecisionState.REQUIRE_HUMAN.value,
                    codes,
                    None,
                    False,
                    None,
                    flight_hash,
                    now,
                )
                return Decision(
                    DecisionState.REQUIRE_HUMAN,
                    bound.to_payload(),
                    bound.digest(),
                    codes,
                    flight_hash=flight_hash,
                )

            return self._issue_and_execute(bound, codes)
        except BaseException as exc:
            return self._indeterminate(request_id, exc, request)

    def _issue_and_execute(self, bound: ActionRequest, codes: list[str]) -> Decision:
        try:
            issued = self.authority.issue(bound)
        except MGKError as exc:
            return self._deny_issue_failure(bound, codes, exc)
        if issued.envelope is None:
            flight_hash = self._flight(
                "DECISION_DENY",
                {"request_id": bound.request_id, "reason_codes": codes},
            )
            now = self.clock.now()
            self.ledger.store_decision(
                bound.request_id,
                bound.request_id,
                DecisionState.DENY.value,
                codes,
                None,
                False,
                None,
                flight_hash,
                now,
            )
            return Decision(
                DecisionState.DENY, bound.to_payload(), bound.digest(), codes, flight_hash=flight_hash
            )
        self._flight(
            "CAPABILITY_ISSUED",
            {
                "request_id": bound.request_id,
                "capability_id": issued.capability_id,
                "action": bound.action,
                "resource": bound.resource,
            },
        )
        result = self.executor.execute(issued.envelope, bound)
        if result.success:
            flight_hash = self._flight(
                "DECISION_ALLOW",
                {
                    "request_id": bound.request_id,
                    "capability_id": issued.capability_id,
                    "output_digest": result.output_digest,
                },
            )
            now = self.clock.now()
            self.ledger.store_decision(
                bound.request_id,
                bound.request_id,
                DecisionState.ALLOW.value,
                codes,
                issued.capability_id,
                True,
                result.output_digest,
                flight_hash,
                now,
            )
            return Decision(
                DecisionState.ALLOW,
                bound.to_payload(),
                bound.digest(),
                codes,
                capability_id=issued.capability_id,
                executed=True,
                output_digest=result.output_digest,
                flight_hash=flight_hash,
            )
        flight_hash = self._flight(
            "DECISION_DENY",
            {"request_id": bound.request_id, "reason_codes": codes, "reason": result.reason_code},
        )
        now = self.clock.now()
        self.ledger.store_decision(
            bound.request_id,
            bound.request_id,
            DecisionState.DENY.value,
            codes,
            issued.capability_id,
            False,
            None,
            flight_hash,
            now,
        )
        return Decision(
            DecisionState.DENY,
            bound.to_payload(),
            bound.digest(),
            codes,
            capability_id=issued.capability_id,
            flight_hash=flight_hash,
        )

    def _deny_issue_failure(
        self, bound: ActionRequest, codes: list[str], exc: MGKError
    ) -> Decision:
        code = getattr(exc, "code", "AUTHORIZATION_DENIED")
        reason_codes = list(codes) + [code]
        flight_hash = self._flight(
            "DECISION_DENY",
            {"request_id": bound.request_id, "reason_codes": reason_codes, "reason": str(exc)},
        )
        now = self.clock.now()
        self.ledger.store_decision(
            bound.request_id,
            bound.request_id,
            DecisionState.DENY.value,
            reason_codes,
            None,
            False,
            None,
            flight_hash,
            now,
        )
        return Decision(
            DecisionState.DENY,
            bound.to_payload(),
            bound.digest(),
            reason_codes,
            flight_hash=flight_hash,
        )

    def _indeterminate(
        self, request_id: str, exc: BaseException, request: dict[str, Any]
    ) -> Decision:
        code = exc.code if isinstance(exc, MGKError) else "UNEXPECTED_EXCEPTION"
        payload = {"request_id": request_id}
        try:
            flight_hash = self._flight(
                "DECISION_INDETERMINATE",
                {"request_id": request_id, "code": code, "reason": str(exc)},
            )
        except BaseException:
            flight_hash = None
        try:
            now = self.clock.now()
            self.ledger.store_decision(
                request_id,
                request_id,
                DecisionState.INDETERMINATE.value,
                [code],
                None,
                False,
                None,
                flight_hash or "",
                now,
            )
        except BaseException:
            pass
        return Decision(
            DecisionState.INDETERMINATE,
            payload,
            "",
            [code],
            flight_hash=flight_hash,
        )

    def pending(self) -> list[dict[str, Any]]:
        return [
            row
            for row in self.ledger.decisions()
            if row["state"] == DecisionState.REQUIRE_HUMAN.value
        ]

    def human_approve(self, request_id: str, operator: str) -> Decision:
        proposal = self.ledger.proposal(request_id)
        if proposal is None:
            return Decision(
                DecisionState.INDETERMINATE,
                {"request_id": request_id},
                "",
                ["PROPOSAL_NOT_FOUND"],
            )
        bound = self._request(proposal)
        decision = "APPROVE"
        signature = self._sign_human(proposal, decision, operator)
        now = self.clock.now()
        action_id = "human-" + request_id
        flight_hash = self._flight(
            "HUMAN_DECISION",
            {
                "request_id": request_id,
                "operator": operator,
                "decision": decision,
                "signature": signature,
            },
        )
        self.ledger.store_human_action(
            action_id, request_id, operator, decision, signature, flight_hash, now
        )
        resolved = self.policy.resolved_context()
        evaluated = self.saxp.evaluate(bound, resolved)
        return self._issue_and_execute_human(
            bound, list(evaluated.reason_codes), operator, signature, resolved
        )

    def human_deny(self, request_id: str, operator: str) -> Decision:
        proposal = self.ledger.proposal(request_id)
        if proposal is None:
            return Decision(
                DecisionState.INDETERMINATE,
                {"request_id": request_id},
                "",
                ["PROPOSAL_NOT_FOUND"],
            )
        bound = self._request(proposal)
        decision = "DENY"
        signature = self._sign_human(proposal, decision, operator)
        now = self.clock.now()
        flight_hash = self._flight(
            "HUMAN_DECISION",
            {
                "request_id": request_id,
                "operator": operator,
                "decision": decision,
                "signature": signature,
            },
        )
        self.ledger.store_human_action(
            "human-" + request_id, request_id, operator, decision, signature, flight_hash, now
        )
        codes = ["HUMAN_DENIED"]
        self.ledger.store_decision(
            request_id,
            request_id,
            DecisionState.DENY.value,
            codes,
            None,
            False,
            None,
            flight_hash,
            now,
        )
        return Decision(
            DecisionState.DENY,
            bound.to_payload(),
            bound.digest(),
            codes,
            human_decision=decision,
            human_signature=signature,
            operator=operator,
            flight_hash=flight_hash,
        )

    def _issue_and_execute_human(
        self,
        bound: ActionRequest,
        codes: list[str],
        operator: str,
        signature: str,
        context: Any,
    ) -> Decision:
        try:
            issued = self.authority.issue(bound, context=context)
        except MGKError as exc:
            code = getattr(exc, "code", "AUTHORIZATION_DENIED")
            reason_codes = list(codes) + [code]
            flight_hash = self._flight(
                "HUMAN_DECISION_DENY",
                {"request_id": bound.request_id, "reason_codes": reason_codes, "reason": str(exc)},
            )
            now = self.clock.now()
            self.ledger.store_decision(
                bound.request_id,
                bound.request_id,
                DecisionState.DENY.value,
                reason_codes,
                None,
                False,
                None,
                flight_hash,
                now,
            )
            return Decision(
                DecisionState.DENY,
                bound.to_payload(),
                bound.digest(),
                reason_codes,
                human_decision="APPROVE",
                human_signature=signature,
                operator=operator,
                flight_hash=flight_hash,
            )
        if issued.envelope is None:
            return Decision(
                DecisionState.DENY,
                bound.to_payload(),
                bound.digest(),
                codes,
                human_decision="APPROVE",
                human_signature=signature,
                operator=operator,
            )
        result = self.executor.execute(issued.envelope, bound)
        state = DecisionState.ALLOW if result.success else DecisionState.DENY
        flight_hash = self._flight(
            "HUMAN_EXECUTION",
            {
                "request_id": bound.request_id,
                "decision": "APPROVE",
                "capability_id": issued.capability_id,
                "executed": result.success,
                "output_digest": result.output_digest,
            },
        )
        now = self.clock.now()
        self.ledger.store_decision(
            bound.request_id,
            bound.request_id,
            state.value,
            codes,
            issued.capability_id,
            result.success,
            result.output_digest,
            flight_hash,
            now,
        )
        return Decision(
            state,
            bound.to_payload(),
            bound.digest(),
            codes,
            capability_id=issued.capability_id,
            executed=result.success,
            output_digest=result.output_digest,
            flight_hash=flight_hash,
            human_decision="APPROVE",
            human_signature=signature,
            operator=operator,
        )

    def _sign_human(self, proposal: dict[str, Any], decision: str, operator: str) -> str:
        if self.operator_key is None:
            return ""
        document = {
            "request_id": proposal["request_id"],
            "request_digest": proposal["request_digest"],
            "decision": decision,
            "operator": operator,
            "timestamp": self.clock.now(),
        }
        from mgk.canonical import canonicalize

        return sign(self.operator_key, HUMAN_GATE_DOMAIN, canonicalize(document))


def new_decision_id() -> str:
    return secrets.token_hex(16)