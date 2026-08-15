from __future__ import annotations

import math
import unicodedata

import pytest


pytestmark = [pytest.mark.unit, pytest.mark.protected]


def test_map_order_does_not_change_canonical_bytes(harness):
    left = {"z": 1, "a": {"q": True, "b": None}, "m": [3, 2, 1]}
    right = {"m": [3, 2, 1], "a": {"b": None, "q": True}, "z": 1}
    assert harness.canonicalize(left) == harness.canonicalize(right)


def test_type_and_value_changes_change_canonical_bytes(harness):
    values = [0, 1, "1", True, False, None, [], {}, {"v": 1}, {"v": "1"}]
    encodings = [harness.canonicalize(value) for value in values]
    assert all(isinstance(item, bytes) for item in encodings)
    assert len(encodings) == len(set(encodings))


def test_unicode_has_one_normal_form_or_is_rejected(harness):
    composed = "é"
    decomposed = unicodedata.normalize("NFD", composed)
    try:
        a = harness.canonicalize({"v": composed})
        b = harness.canonicalize({"v": decomposed})
    except (TypeError, ValueError):
        return
    assert a == b, "Unicode normalization differential"


@pytest.mark.parametrize("value", [math.nan, math.inf, -math.inf])
def test_non_finite_numbers_are_rejected(harness, value):
    with pytest.raises((TypeError, ValueError, OverflowError)):
        harness.canonicalize({"v": value})


def test_canonicalization_is_idempotent_at_boundary(harness):
    value = {"scope": ["read", "write"], "epoch": 7, "payload": {"x": 1}}
    first = harness.canonicalize(value)
    assert first == harness.canonicalize(value)

