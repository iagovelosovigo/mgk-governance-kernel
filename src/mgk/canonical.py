"""MGK Canonical JSON v1.

The format deliberately excludes floating point numbers and duplicate object keys. Strings
must contain Unicode scalar values, integers are restricted to the interoperable signed
53-bit range, object keys are ordered by Unicode code point and the only accepted wire form
is the exact UTF-8 encoding emitted here.
"""

from __future__ import annotations

import hashlib
import json
import unicodedata
from typing import Any

from .errors import CanonicalizationError

MAX_CANONICAL_BYTES = 256 * 1024
MAX_DEPTH = 32
MAX_ITEMS = 4096
MIN_INTEGER = -(2**53) + 1
MAX_INTEGER = 2**53 - 1


def _reject_float(_value: str) -> None:
    raise CanonicalizationError("floating point values are forbidden")


def _reject_constant(_value: str) -> None:
    raise CanonicalizationError("non-finite values are forbidden")


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CanonicalizationError(f"duplicate object key: {key!r}")
        result[key] = value
    return result


def _validate(value: Any, depth: int = 0, budget: list[int] | None = None) -> None:
    if budget is None:
        budget = [MAX_ITEMS]
    budget[0] -= 1
    if budget[0] < 0:
        raise CanonicalizationError("document item limit exceeded")
    if depth > MAX_DEPTH:
        raise CanonicalizationError("document nesting limit exceeded")
    if value is None or type(value) is bool:
        return
    if type(value) is int:
        if not MIN_INTEGER <= value <= MAX_INTEGER:
            raise CanonicalizationError("integer outside interoperable range")
        return
    if type(value) is str:
        if any(0xD800 <= ord(char) <= 0xDFFF for char in value):
            raise CanonicalizationError("surrogate code points are forbidden")
        return
    if type(value) is list:
        for item in value:
            _validate(item, depth + 1, budget)
        return
    if type(value) is dict:
        for key, item in value.items():
            if type(key) is not str:
                raise CanonicalizationError("object keys must be strings")
            _validate(key, depth + 1, budget)
            _validate(item, depth + 1, budget)
        return
    raise CanonicalizationError(f"unsupported value type: {type(value).__name__}")


def _normalize(value: Any) -> Any:
    if type(value) is str:
        return unicodedata.normalize("NFC", value)
    if type(value) is list:
        return [_normalize(item) for item in value]
    if type(value) is dict:
        result: dict[str, Any] = {}
        for key, item in value.items():
            normalized_key = _normalize(key)
            if normalized_key in result:
                raise CanonicalizationError("object keys collide after NFC normalization")
            result[normalized_key] = _normalize(item)
        return result
    return value


def canonicalize(value: Any) -> bytes:
    normalized = _normalize(value)
    _validate(normalized)
    try:
        encoded = json.dumps(
            normalized,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8", "strict")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise CanonicalizationError(str(exc)) from exc
    if len(encoded) > MAX_CANONICAL_BYTES:
        raise CanonicalizationError("canonical document exceeds size limit")
    return encoded


def parse_canonical(data: bytes) -> Any:
    if type(data) is not bytes or not data or len(data) > MAX_CANONICAL_BYTES:
        raise CanonicalizationError("invalid canonical byte document")
    try:
        text = data.decode("utf-8", "strict")
        value = json.loads(
            text,
            object_pairs_hook=_pairs,
            parse_float=_reject_float,
            parse_constant=_reject_constant,
        )
    except CanonicalizationError:
        raise
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise CanonicalizationError(str(exc)) from exc
    _validate(value)
    if canonicalize(value) != data:
        raise CanonicalizationError("wire document is not canonical")
    return value


def digest(value: Any) -> str:
    return hashlib.sha256(canonicalize(value)).hexdigest()
