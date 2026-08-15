from __future__ import annotations

import pytest

from api_contract import SAXP_OUTCOMES, request
from tests.helpers import Counter, assert_denied


pytestmark = [pytest.mark.unit, pytest.mark.protected]


@pytest.mark.parametrize(
    ("context", "expected"),
    [
        ({"permitted": True, "evidence_complete": True}, "TEN_XEITO"),
        ({"permitted": True, "evidence_complete": False}, "REQUIRE_XEITO"),
        ({"permitted": False, "evidence_complete": True}, "NON_TEN_XEITO"),
    ],
)
def test_saxp_three_binding_outcomes(harness, context, expected):
    proposal = harness.propose(request())
    decision = harness.evaluate(proposal, context)
    assert decision.get("outcome") in SAXP_OUTCOMES
    assert decision["outcome"] == expected


def test_unknown_or_incomplete_context_is_not_ten_xeito(harness):
    decision = harness.evaluate(harness.propose(request()), {})
    assert decision.get("outcome") in {"REQUIRE_XEITO", "NON_TEN_XEITO"}


@pytest.mark.parametrize("outcome", ["REQUIRE_XEITO", "NON_TEN_XEITO"])
def test_non_ten_xeito_cannot_be_turned_into_execution(harness, outcome):
    req = request(payload={"decision": outcome})
    context = {
        "permitted": outcome != "NON_TEN_XEITO",
        "evidence_complete": outcome != "REQUIRE_XEITO",
    }
    decision = harness.evaluate(harness.propose(req), context)
    assert decision["outcome"] == outcome
    forged = harness.assemble(
        {"request": req, "decision": decision, "nonce": "fake"}, b"\x00" * 64
    )
    counter = Counter()
    assert_denied(harness.execute(forged, req, counter.operation), counter)

