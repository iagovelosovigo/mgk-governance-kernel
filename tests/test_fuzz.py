import os

import pytest
from hypothesis import HealthCheck, given, settings, strategies as st

from mgk.canonical import parse_canonical


@pytest.mark.adversarial
@pytest.mark.property
@settings(max_examples=500, deadline=None)
@given(st.binary(min_size=0, max_size=2048))
def test_random_wire_input_never_escapes_as_system_exit_or_crash(data):
    try:
        parse_canonical(data)
    except Exception:
        pass


@pytest.mark.adversarial
@pytest.mark.property
@settings(
    max_examples=200,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
@given(st.binary(min_size=0, max_size=512))
def test_random_capability_input_never_executes(kernel_factory, data):
    kernel = kernel_factory("fuzz")
    from .helpers import read_request

    result = kernel.executor.execute(data, read_request())
    assert result.success is False
    assert result.execution_authority == 0
