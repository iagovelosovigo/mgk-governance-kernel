from __future__ import annotations

import pytest

from mgk.canonical import (
    MAX_DEPTH,
    MAX_INTEGER,
    MIN_INTEGER,
    canonicalize,
    digest,
    parse_canonical,
)
from mgk.errors import CanonicalizationError


def test_canonicalize_sorts_keys_and_round_trips():
    value = {"z": 1, "a": [3, 2, 1], "m": {"y": True, "x": None}}
    encoded = canonicalize(value)
    assert encoded == b'{"a":[3,2,1],"m":{"x":null,"y":true},"z":1}'
    assert parse_canonical(encoded) == value
    assert digest(value) == digest(parse_canonical(encoded))


def test_canonicalize_accepts_scalars():
    assert canonicalize(None) == b"null"
    assert canonicalize(True) == b"true"
    assert canonicalize(False) == b"false"
    assert canonicalize(0) == b"0"
    assert canonicalize(-1) == b"-1"
    assert canonicalize("héllo") == '"héllo"'.encode("utf-8")


def test_canonicalize_integer_bounds():
    assert canonicalize(MIN_INTEGER) == b"-%d" % 9007199254740991
    assert canonicalize(MAX_INTEGER) == b"9007199254740991"
    with pytest.raises(CanonicalizationError, match="^integer outside interoperable range$"):
        canonicalize(MIN_INTEGER - 1)
    with pytest.raises(CanonicalizationError, match="^integer outside interoperable range$"):
        canonicalize(MAX_INTEGER + 1)


def test_canonicalize_rejects_floats():
    with pytest.raises(CanonicalizationError, match="^unsupported value type: float$"):
        canonicalize(1.5)


def test_canonicalize_rejects_surrogates():
    with pytest.raises(CanonicalizationError, match="^surrogate code points are forbidden$"):
        canonicalize("\ud800")


def test_canonicalize_rejects_non_string_keys():
    with pytest.raises(CanonicalizationError, match="^object keys must be strings$"):
        canonicalize({1: "a"})


def test_canonicalize_rejects_unsupported_type():
    class Weird:
        pass

    with pytest.raises(CanonicalizationError, match="^unsupported value type: Weird$"):
        canonicalize(Weird())


def test_canonicalize_detects_nfc_collision():
    value = {"\u00e9": 1, "e\u0301": 2}
    with pytest.raises(CanonicalizationError, match="^object keys collide after NFC normalization$"):
        canonicalize(value)


def test_canonicalize_nesting_limit():
    deep = 0
    for _ in range(MAX_DEPTH + 2):
        deep = [deep]
    with pytest.raises(CanonicalizationError, match="^document nesting limit exceeded$"):
        canonicalize(deep)


def test_canonicalize_size_limit():
    with pytest.raises(CanonicalizationError, match="^canonical document exceeds size limit$"):
        canonicalize("x" * (256 * 1024 + 1))


def test_parse_canonical_rejects_invalid_byte_documents():
    for bad in (None, b"", "not-bytes"):
        with pytest.raises(CanonicalizationError, match="^invalid canonical byte document$"):
            parse_canonical(bad)


def test_parse_canonical_rejects_float_and_constant():
    with pytest.raises(CanonicalizationError, match="^floating point values are forbidden$"):
        parse_canonical(b'{"a": 1.5}')
    with pytest.raises(CanonicalizationError, match="^non-finite values are forbidden$"):
        parse_canonical(b'{"a": NaN}')


def test_parse_canonical_rejects_duplicate_keys():
    with pytest.raises(CanonicalizationError, match="^duplicate object key: 'a'$"):
        parse_canonical(b'{"a": 1, "a": 2}')


def test_parse_canonical_rejects_non_canonical_wire():
    with pytest.raises(CanonicalizationError, match="^wire document is not canonical$"):
        parse_canonical(b'{"b": 1, "a": 2}')
    with pytest.raises(CanonicalizationError, match="^wire document is not canonical$"):
        parse_canonical(b'{"a": 1 }')


def test_parse_canonical_rejects_malformed_json():
    with pytest.raises(CanonicalizationError):
        parse_canonical(b"{not json}")


def test_parse_canonical_pretty_json_rejected():
    with pytest.raises(CanonicalizationError, match="^wire document is not canonical$"):
        parse_canonical(b'{"a":1}\n')