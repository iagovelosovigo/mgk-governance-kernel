from __future__ import annotations

import pytest

from mgk.crypto import (
    CAPABILITY_DOMAIN,
    b64u_decode,
    b64u_encode,
    generate_private_key,
    key_id,
    load_private_key,
    load_public_key,
    private_key_bytes,
    public_key_bytes,
    sign,
    verify,
)
from mgk.errors import SignatureError


def test_private_key_serialization_round_trip():
    key = generate_private_key()
    raw = private_key_bytes(key)
    assert isinstance(raw, bytes)
    assert len(raw) == 32
    restored = load_private_key(raw)
    assert public_key_bytes(restored.public_key()) == public_key_bytes(key.public_key())
    assert key_id(restored.public_key()) == key_id(key.public_key())


def test_public_key_serialization_round_trip():
    key = generate_private_key()
    raw = public_key_bytes(key.public_key())
    assert isinstance(raw, bytes)
    assert len(raw) == 32
    restored = load_public_key(raw)
    assert key_id(restored) == key_id(key.public_key())


def test_load_private_key_rejects_invalid_inputs():
    for bad in (None, "not-bytes", b"short", b"\x00" * 31, b"\x00" * 33, b"\x00" * 0):
        with pytest.raises(SignatureError, match="^invalid Ed25519 private key$"):
            load_private_key(bad)


def test_load_public_key_rejects_invalid_inputs():
    for bad in (None, "not-bytes", b"short", b"\x00" * 31, b"\x00" * 33):
        with pytest.raises(SignatureError, match="^invalid Ed25519 public key$"):
            load_public_key(bad)


def test_key_id_format():
    key = generate_private_key()
    identifier = key_id(key.public_key())
    assert identifier.startswith("ed25519:")
    assert len(identifier) == len("ed25519:") + 64


def test_b64u_encode_strips_padding():
    assert b64u_encode(b"a") == "YQ"
    assert b64u_encode(b"ab") == "YWI"
    assert b64u_encode(b"abc") == "YWJj"
    assert b64u_encode(b"\x00\x01\x02") == "AAEC"


def test_b64u_encode_does_not_strip_trailing_alphabet_byte():
    assert b64u_encode(b"\x00\x00\x17") == "AAAX"


def test_b64u_decode_rejects_each_invalid_form():
    cases = [
        (None, "invalid base64url value"),
        (123, "invalid base64url value"),
        ("", "invalid base64url value"),
        ("  ", "invalid base64url value"),
        ("YW Jj", "invalid base64url value"),
        ("YWI=", "padded base64url is not canonical"),
        ("YWI==", "padded base64url is not canonical"),
        ("!!!", "invalid base64url encoding"),
    ]
    for value, message in cases:
        with pytest.raises(SignatureError) as exc:
            b64u_decode(value)
        assert str(exc.value) == message


def test_b64u_decode_rejects_non_canonical_encodings():
    for value in ("AB", "AAB"):
        with pytest.raises(SignatureError, match="^non-canonical base64url encoding$"):
            b64u_decode(value)
    assert b64u_encode(b"a") == "YQ"
    assert b64u_decode("YQ") == b"a"


def test_b64u_decode_expected_size_boundary():
    raw = b"0" * 32
    encoded = b64u_encode(raw)
    assert b64u_decode(encoded, 32) == raw
    with pytest.raises(SignatureError, match="^unexpected decoded size$"):
        b64u_decode(encoded, 31)
    with pytest.raises(SignatureError, match="^unexpected decoded size$"):
        b64u_decode(encoded, 33)


def test_b64u_decode_accepts_canonical_forms():
    assert b64u_decode("YQ") == b"a"
    assert b64u_decode("YWI") == b"ab"
    assert b64u_decode("YWJj") == b"abc"
    assert b64u_decode("AAEC") == b"\x00\x01\x02"


def test_sign_and_verify_round_trip():
    key = generate_private_key()
    signature = sign(key, CAPABILITY_DOMAIN, b"message")
    verify(key.public_key(), CAPABILITY_DOMAIN, b"message", signature)


def test_verify_rejects_bad_signature():
    key = generate_private_key()
    signature = sign(key, CAPABILITY_DOMAIN, b"message")
    with pytest.raises(SignatureError, match="^Ed25519 signature verification failed$"):
        verify(key.public_key(), CAPABILITY_DOMAIN, b"other", signature)


def test_verify_rejects_wrong_key():
    key = generate_private_key()
    other = generate_private_key()
    signature = sign(key, CAPABILITY_DOMAIN, b"message")
    with pytest.raises(SignatureError, match="^Ed25519 signature verification failed$"):
        verify(other.public_key(), CAPABILITY_DOMAIN, b"message", signature)


def test_verify_rejects_short_signature():
    key = generate_private_key()
    with pytest.raises(SignatureError, match="^unexpected decoded size$"):
        verify(key.public_key(), CAPABILITY_DOMAIN, b"message", "YQ")