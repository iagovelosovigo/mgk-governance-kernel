from __future__ import annotations

import copy

import pytest
from hypothesis import given, settings, strategies as st

from api_contract import request
from tests.helpers import Counter, assert_denied


pytestmark = [pytest.mark.property, pytest.mark.protected]

json_scalars = st.one_of(
    st.none(), st.booleans(), st.integers(min_value=-(2**53) + 1, max_value=2**53 - 1),
    st.text(max_size=64),
)
json_values = st.recursive(
    json_scalars,
    lambda children: st.one_of(
        st.lists(children, max_size=8),
        st.dictionaries(st.text(max_size=24), children, max_size=8),
    ),
    max_leaves=24,
)


@given(json_values)
@settings(max_examples=250, deadline=None)
def test_canonicalization_is_deterministic(harness, value):
    first = harness.canonicalize(copy.deepcopy(value))
    second = harness.canonicalize(copy.deepcopy(value))
    assert isinstance(first, bytes)
    assert first == second


@given(st.dictionaries(st.text(min_size=1, max_size=20), json_values, max_size=10))
@settings(max_examples=150, deadline=None)
def test_map_insertion_order_is_irrelevant(harness, mapping):
    reversed_mapping = dict(reversed(list(mapping.items())))
    assert harness.canonicalize(mapping) == harness.canonicalize(reversed_mapping)


@given(
    action=st.text(min_size=1, max_size=32),
    resource=st.text(min_size=1, max_size=64),
    payload=json_values,
)
@settings(max_examples=150, deadline=None)
def test_request_binding_rejects_any_resource_change(harness, action, resource, payload):
    req = request(action=action, resource=resource, payload=payload)
    cap = harness.issue(req)
    changed = request(action=action, resource=resource + "#changed", payload=payload)
    counter = Counter()
    assert_denied(harness.execute(cap, changed, counter.operation), counter)


@given(delta=st.integers(min_value=1, max_value=86_400))
@settings(max_examples=80, deadline=None)
def test_expiration_never_authorizes_after_boundary(harness, clock, delta):
    req = request()
    cap = harness.issue(
        req,
        issued_at=clock.now,
        expires_at=clock.now + delta,
        nonce=f"n-exp-{delta}",
    )
    clock.advance(delta + 1)
    counter = Counter()
    assert_denied(harness.execute(cap, req, counter.operation), counter)

