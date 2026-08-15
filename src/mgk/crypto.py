"""Ed25519 authority keys and domain-separated signatures."""

from __future__ import annotations

import base64
import hashlib

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .errors import SignatureError

CAPABILITY_DOMAIN = b"MGK-CAPABILITY-V1\x00"
AUDIT_DOMAIN = b"MGK-AUDIT-CHECKPOINT-V1\x00"
EPOCH_DOMAIN = b"MGK-EPOCH-V1\x00"


def generate_private_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


def public_key_bytes(key: Ed25519PublicKey) -> bytes:
    return key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def private_key_bytes(key: Ed25519PrivateKey) -> bytes:
    return key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )


def load_private_key(raw: bytes) -> Ed25519PrivateKey:
    if type(raw) is not bytes or len(raw) != 32:
        raise SignatureError("invalid Ed25519 private key")
    return Ed25519PrivateKey.from_private_bytes(raw)


def load_public_key(raw: bytes) -> Ed25519PublicKey:
    if type(raw) is not bytes or len(raw) != 32:
        raise SignatureError("invalid Ed25519 public key")
    return Ed25519PublicKey.from_public_bytes(raw)


def key_id(key: Ed25519PublicKey) -> str:
    return "ed25519:" + hashlib.sha256(public_key_bytes(key)).hexdigest()


def b64u_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def b64u_decode(value: str, expected_size: int | None = None) -> bytes:
    if type(value) is not str or not value or any(char.isspace() for char in value):
        raise SignatureError("invalid base64url value")
    if "=" in value:
        raise SignatureError("padded base64url is not canonical")
    try:
        raw = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    except Exception as exc:
        raise SignatureError("invalid base64url encoding") from exc
    if b64u_encode(raw) != value:
        raise SignatureError("non-canonical base64url encoding")
    if expected_size is not None and len(raw) != expected_size:
        raise SignatureError("unexpected decoded size")
    return raw


def sign(key: Ed25519PrivateKey, domain: bytes, message: bytes) -> str:
    return b64u_encode(key.sign(domain + message))


def verify(key: Ed25519PublicKey, domain: bytes, message: bytes, signature: str) -> None:
    raw = b64u_decode(signature, 64)
    try:
        key.verify(raw, domain + message)
    except InvalidSignature as exc:
        raise SignatureError("Ed25519 signature verification failed") from exc
