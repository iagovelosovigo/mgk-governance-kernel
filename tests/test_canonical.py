import json

import pytest
from hypothesis import given, settings, strategies as st

from mgk.canonical import canonicalize, parse_canonical
from mgk.errors import CanonicalizationError


def test_object_order_is_deterministic():
    assert canonicalize({"z": 1, "a": 2}) == b'{"a":2,"z":1}'


@pytest.mark.parametrize(
    "wire",
    [
        b'{"a": 1}',
        b'{"a":1}\n',
        b'{"b":1,"a":2}',
        b'{"a":1,"a":2}',
        b'{"a":1.0}',
        b'{"a":NaN}',
        b'\xff',
        b'',
    ],
)
def test_noncanonical_or_ambiguous_wire_is_rejected(wire):
    with pytest.raises(CanonicalizationError):
        parse_canonical(wire)


def test_floats_and_large_integers_are_rejected():
    with pytest.raises(CanonicalizationError):
        canonicalize({"value": 0.5})
    with pytest.raises(CanonicalizationError):
        canonicalize({"value": 2**60})


def test_surrogates_are_rejected():
    with pytest.raises(CanonicalizationError):
        canonicalize({"value": "\ud800"})


scalar = st.none() | st.booleans() | st.integers(min_value=-(2**53) + 1, max_value=2**53 - 1) | st.text(
    alphabet=st.characters(blacklist_categories=("Cs",)), max_size=30
)
documents = st.recursive(
    scalar,
    lambda children: st.lists(children, max_size=8)
    | st.dictionaries(st.text(alphabet=st.characters(blacklist_categories=("Cs",)), max_size=12), children, max_size=8),
    max_leaves=30,
)


@pytest.mark.property
@settings(max_examples=250, deadline=None)
@given(documents)
def test_canonical_round_trip_property(document):
    wire = canonicalize(document)
    assert canonicalize(parse_canonical(wire)) == wire


@pytest.mark.property
@settings(max_examples=100, deadline=None)
@given(st.dictionaries(st.text(min_size=1, max_size=8), st.integers(-1000, 1000), min_size=1, max_size=12))
def test_pretty_json_is_never_accepted_as_canonical(document):
    pretty = json.dumps(document, ensure_ascii=False, sort_keys=True, indent=2).encode()
    if pretty != canonicalize(document):
        with pytest.raises(CanonicalizationError):
            parse_canonical(pretty)
