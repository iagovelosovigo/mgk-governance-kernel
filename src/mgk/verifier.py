"""Fail-closed capability verification and atomic replay consumption."""

from __future__ import annotations

import re
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .canonical import canonicalize, digest, parse_canonical
from .clock import SystemClock
from .crypto import CAPABILITY_DOMAIN, key_id, verify
from .errors import EpochError, SchemaError, ScopeError, TimeWindowError
from .models import ActionRequest
from .saxp import SAXPResult
from .state import SecurityState

_HEX32 = re.compile(r"^[0-9a-f]{32}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
PAYLOAD_KEYS = {
    "audience",
    "authorization_epoch",
    "capability_id",
    "expires_at",
    "issued_at",
    "issuer",
    "nonce",
    "request_digest",
    "resource_binding",
    "saxp",
    "schema",
    "scope",
    "subject",
}


class CapabilityVerifier:
    def __init__(
        self,
        public_key: Ed25519PublicKey,
        state: SecurityState,
        clock: object | None = None,
        maximum_ttl_seconds: int = 300,
        clock_skew_seconds: int = 5,
    ):
        self.public_key = public_key
        self.state = state
        self.clock = clock or SystemClock()
        self.maximum_ttl_seconds = maximum_ttl_seconds
        self.clock_skew_seconds = clock_skew_seconds

    @staticmethod
    def _require_string(value: Any, name: str) -> str:
        if type(value) is not str or not value or len(value.encode("utf-8")) > 4096:
            raise SchemaError(f"invalid {name}")
        return value

    def _validate_payload(self, payload: Any, request: ActionRequest) -> dict[str, Any]:
        if type(payload) is not dict or set(payload) != PAYLOAD_KEYS:
            raise SchemaError("invalid capability payload schema")
        if payload["schema"] != "mgk-capability/v1":
            raise SchemaError("unsupported capability schema")
        for name in ("issuer", "subject", "audience", "capability_id", "request_digest", "nonce"):
            self._require_string(payload[name], name)
        if not _HEX32.fullmatch(payload["nonce"]):
            raise SchemaError("invalid nonce")
        if not _HEX64.fullmatch(payload["capability_id"]) or not _HEX64.fullmatch(
            payload["request_digest"]
        ):
            raise SchemaError("invalid capability digest")
        base = dict(payload)
        capability_id = base.pop("capability_id")
        if digest(base) != capability_id:
            raise SchemaError("capability identifier mismatch")

        scope = payload["scope"]
        if type(scope) is not dict or set(scope) != {"action", "resource"}:
            raise ScopeError("invalid capability scope")
        if scope != {"action": request.action, "resource": request.resource}:
            raise ScopeError("capability scope does not match execution request")
        if payload["subject"] != request.principal or payload["audience"] != request.audience:
            raise ScopeError("subject or audience mismatch")
        if payload["request_digest"] != request.digest():
            raise ScopeError("request payload mutation detected")

        saxp = payload["saxp"]
        expected_saxp = {"context_digest", "policy_id", "reason_codes", "request_digest", "result"}
        if type(saxp) is not dict or set(saxp) != expected_saxp:
            raise SchemaError("invalid SAXP evidence")
        if saxp["result"] != SAXPResult.TEN_XEITO.value:
            raise ScopeError("capability lacks TEN_XEITO")
        if saxp["request_digest"] != request.digest():
            raise ScopeError("SAXP evidence is not bound to the request")
        if type(saxp["reason_codes"]) is not list or not saxp["reason_codes"]:
            raise SchemaError("invalid SAXP reason evidence")

        action = request.action
        binding = payload["resource_binding"]
        if type(binding) is not dict or binding.get("path") != request.resource:
            raise ScopeError("resource binding mismatch")
        if action in {"resource.read", "sandbox.read_file", "sandbox.read_record"}:
            if set(binding) != {"path", "sha256", "size", "state"} or binding["state"] != "present":
                raise ScopeError("invalid read resource binding")
        elif action in {"resource.create", "sandbox.create_record"}:
            expected = {"path", "post_sha256", "post_size", "state"}
            if set(binding) != expected or binding["state"] != "absent":
                raise ScopeError("invalid create resource binding")
        elif action == "sandbox.write_file":
            expected = {
                "path",
                "post_sha256",
                "post_size",
                "pre_sha256",
                "pre_size",
                "pre_state",
                "state",
            }
            if set(binding) != expected or binding["state"] != "write":
                raise ScopeError("invalid write resource binding")
            if binding["pre_state"] not in {"present", "absent"}:
                raise ScopeError("invalid write pre-state")
        elif action == "sandbox.append_file":
            expected = {"path", "post_sha256", "post_size", "pre_sha256", "pre_size", "state"}
            if set(binding) != expected or binding["state"] != "append":
                raise ScopeError("invalid append resource binding")
        else:
            raise ScopeError("unsupported capability action")
        return payload

    def verify(self, envelope_bytes: bytes, request: ActionRequest, consume_nonce: bool = True) -> dict[str, Any]:
        envelope = parse_canonical(envelope_bytes)
        if type(envelope) is not dict or set(envelope) != {"algorithm", "key_id", "payload", "signature"}:
            raise SchemaError("invalid capability envelope")
        if envelope["algorithm"] != "Ed25519" or envelope["key_id"] != key_id(self.public_key):
            raise SchemaError("unexpected capability signer")
        payload = self._validate_payload(envelope["payload"], request)
        verify(
            self.public_key,
            CAPABILITY_DOMAIN,
            canonicalize(payload),
            envelope["signature"],
        )

        issued_at = payload["issued_at"]
        expires_at = payload["expires_at"]
        if type(issued_at) is not int or type(expires_at) is not int:
            raise TimeWindowError("capability timestamps must be integers")
        if expires_at <= issued_at or expires_at - issued_at > self.maximum_ttl_seconds:
            raise TimeWindowError("invalid capability validity window")
        now = self.clock.now()
        if issued_at > now + self.clock_skew_seconds or now >= expires_at:
            raise TimeWindowError("capability is not currently valid")

        epoch = payload["authorization_epoch"]
        if type(epoch) is not int or epoch != self.state.current_epoch():
            raise EpochError("stale or invalid authorization epoch")
        if consume_nonce:
            self.state.consume_nonce(payload["nonce"], payload["capability_id"], now)
        return payload
