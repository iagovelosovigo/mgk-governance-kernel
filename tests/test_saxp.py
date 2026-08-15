from dataclasses import replace

import pytest

from mgk import SAXPContext, SAXPEvaluator, SAXPResult

from .conftest import SAFE_CONTEXT
from .helpers import read_request


def evaluate(context):
    return SAXPEvaluator().evaluate(read_request(), context)


def test_ten_xeito_is_eligible():
    assert evaluate(SAFE_CONTEXT).result == SAXPResult.TEN_XEITO


@pytest.mark.parametrize(
    "context,reason",
    [
        (replace(SAFE_CONTEXT, information_complete=False), "INFORMATION_INCOMPLETE"),
        (replace(SAFE_CONTEXT, critical_uncertainty=True), "CRITICAL_UNCERTAINTY"),
        (replace(SAFE_CONTEXT, sentidino=4999), "SENTIDINO_RECALIBRATION_REQUIRED"),
    ],
)
def test_require_xeito_blocks_and_requests_recalibration(context, reason):
    decision = evaluate(context)
    assert decision.result == SAXPResult.REQUIRE_XEITO
    assert reason in decision.reason_codes


@pytest.mark.parametrize(
    "context,reason",
    [
        (replace(SAFE_CONTEXT, control_risk=True), "CONTROL_RISK"),
        (replace(SAFE_CONTEXT, ethical_constraints_satisfied=False), "ETHICAL_CONSTRAINT_FAILED"),
        (replace(SAFE_CONTEXT, coherence_delta=-1), "COHERENCE_DECREASE"),
        (replace(SAFE_CONTEXT, systemic_pressure=101), "THRESHOLD_K_EXCEEDED"),
    ],
)
def test_non_ten_xeito_is_binding_denial(context, reason):
    decision = evaluate(context)
    assert decision.result == SAXPResult.NON_TEN_XEITO
    assert reason in decision.reason_codes


def test_require_xeito_never_mints_capability(kernel_factory):
    kernel = kernel_factory()
    request = read_request("require")
    kernel.contexts.values[request.request_id] = replace(SAFE_CONTEXT, information_complete=False)
    issued = kernel.authority.issue(request)
    assert issued.envelope is None
    assert issued.decision.result == SAXPResult.REQUIRE_XEITO


def test_non_ten_xeito_never_mints_capability(kernel_factory):
    kernel = kernel_factory()
    request = read_request("non")
    kernel.contexts.values[request.request_id] = replace(SAFE_CONTEXT, control_risk=True)
    issued = kernel.authority.issue(request)
    assert issued.envelope is None
    assert issued.decision.result == SAXPResult.NON_TEN_XEITO
