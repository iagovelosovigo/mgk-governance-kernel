"""Capability issuance owned by deterministic policy, never by the planner."""

from __future__ import annotations

import re
import secrets
from dataclasses import dataclass
from typing import Callable

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .canonical import canonicalize, digest
from .clock import SystemClock
from .crypto import CAPABILITY_DOMAIN, b64u_decode, key_id, sign
from .errors import AuthorizationDenied, SchemaError
from .models import ActionRequest, IssueResult, SAXPContext
from .resource import MAX_RESOURCE_BYTES, ResourceGuard
from .saxp import SAXPEvaluator, SAXPResult
from .state import SecurityState

_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,127}$")

SANDBOX_ACTIONS = frozenset(
    {
        "sandbox.read_file",
        "sandbox.write_file",
        "sandbox.append_file",
        "sandbox.create_record",
        "sandbox.read_record",
    }
)


@dataclass(frozen=True)
class AuthorityPolicy:
    policy_id: str = "mgk-authority-v1"
    allowed_actions: frozenset[str] = frozenset({"resource.read", "resource.create"})
    allowed_principals: frozenset[str] = frozenset({"planner"})
    allowed_audiences: frozenset[str] = frozenset({"executor"})
    allowed_resource_prefixes: tuple[str, ...] = ("workspace/",)
    default_ttl_seconds: int = 60
    maximum_ttl_seconds: int = 300

    def validate(self) -> None:
        if not self.policy_id or not self.allowed_actions:
            raise ValueError("invalid authority policy")
        if not self.allowed_principals or not self.allowed_audiences:
            raise ValueError("authority policy needs principals and audiences")
        if not self.allowed_resource_prefixes:
            raise ValueError("authority policy needs resource prefixes")
        if not 1 <= self.default_ttl_seconds <= self.maximum_ttl_seconds <= 3600:
            raise ValueError("invalid capability TTL policy")


class CapabilityAuthority:
    def __init__(
        self,
        issuer: str,
        private_key: Ed25519PrivateKey,
        state: SecurityState,
        resource_guard: ResourceGuard,
        context_provider: Callable[[ActionRequest], SAXPContext],
        saxp: SAXPEvaluator | None = None,
        policy: AuthorityPolicy | None = None,
        clock: object | None = None,
    ):
        if not _IDENTIFIER.fullmatch(issuer):
            raise ValueError("invalid issuer")
        self.issuer = issuer
        self.__private_key = private_key
        self.state = state
        self.resource_guard = resource_guard
        self.context_provider = context_provider
        self.saxp = saxp or SAXPEvaluator()
        self.policy = policy or AuthorityPolicy()
        self.policy.validate()
        self.clock = clock or SystemClock()

    def _validate_request(self, request: ActionRequest) -> None:
        for value in (
            request.request_id,
            request.principal,
            request.audience,
            request.action,
        ):
            if not _IDENTIFIER.fullmatch(value):
                raise SchemaError("invalid request identifier")
        request.digest()
        if request.action not in self.policy.allowed_actions:
            raise AuthorizationDenied("action is outside authority policy")
        if request.principal not in self.policy.allowed_principals:
            raise AuthorizationDenied("principal is outside authority policy")
        if request.audience not in self.policy.allowed_audiences:
            raise AuthorizationDenied("audience is outside authority policy")
        if not any(request.resource.startswith(prefix) for prefix in self.policy.allowed_resource_prefixes):
            raise AuthorizationDenied("resource is outside authority policy")

    def _bind_resource(self, request: ActionRequest) -> dict[str, object]:
        parameters = dict(request.parameters)
        if request.action == "resource.read":
            if parameters:
                raise SchemaError("resource.read takes no parameters")
            return self.resource_guard.bind_present(request.resource)
        if request.action == "resource.create":
            if set(parameters) != {"content_b64"} or type(parameters["content_b64"]) is not str:
                raise SchemaError("resource.create requires canonical content_b64")
            data = b64u_decode(parameters["content_b64"])
            if len(data) > MAX_RESOURCE_BYTES:
                raise SchemaError("create payload exceeds size limit")
            import hashlib

            return self.resource_guard.bind_absent(
                request.resource,
                hashlib.sha256(data).hexdigest(),
                len(data),
            )
        if request.action == "sandbox.read_file" or request.action == "sandbox.read_record":
            if parameters:
                raise SchemaError(f"{request.action} takes no parameters")
            return self.resource_guard.bind_present(request.resource)
        if request.action == "sandbox.write_file":
            if set(parameters) != {"content_b64"} or type(parameters["content_b64"]) is not str:
                raise SchemaError("sandbox.write_file requires canonical content_b64")
            data = b64u_decode(parameters["content_b64"])
            return self.resource_guard.bind_write(request.resource, data)
        if request.action == "sandbox.append_file":
            if set(parameters) != {"content_b64"} or type(parameters["content_b64"]) is not str:
                raise SchemaError("sandbox.append_file requires canonical content_b64")
            data = b64u_decode(parameters["content_b64"])
            return self.resource_guard.bind_append(request.resource, data)
        if request.action == "sandbox.create_record":
            if set(parameters) != {"content_b64"} or type(parameters["content_b64"]) is not str:
                raise SchemaError("sandbox.create_record requires canonical content_b64")
            data = b64u_decode(parameters["content_b64"])
            import hashlib

            return self.resource_guard.bind_absent(
                request.resource,
                hashlib.sha256(data).hexdigest(),
                len(data),
            )
        raise AuthorizationDenied("unsupported action")

    def issue(
        self,
        request: ActionRequest,
        ttl_seconds: int | None = None,
        context: SAXPContext | None = None,
    ) -> IssueResult:
        self._validate_request(request)
        if context is None:
            context = self.context_provider(request)
        if not isinstance(context, SAXPContext):
            raise SchemaError("trusted context provider returned an invalid context")
        decision = self.saxp.evaluate(request, context)
        if decision.result != SAXPResult.TEN_XEITO.value:
            return IssueResult(envelope=None, decision=decision, capability_id=None)

        ttl = self.policy.default_ttl_seconds if ttl_seconds is None else ttl_seconds
        if type(ttl) is not int or not 1 <= ttl <= self.policy.maximum_ttl_seconds:
            raise AuthorizationDenied("capability TTL exceeds authority policy")
        resource_binding = self._bind_resource(request)
        now = self.clock.now()
        epoch = self.state.current_epoch()
        base_payload = {
            "audience": request.audience,
            "authorization_epoch": epoch,
            "expires_at": now + ttl,
            "issued_at": now,
            "issuer": self.issuer,
            "nonce": secrets.token_hex(16),
            "request_digest": request.digest(),
            "resource_binding": resource_binding,
            "saxp": decision.to_payload(),
            "schema": "mgk-capability/v1",
            "scope": {"action": request.action, "resource": request.resource},
            "subject": request.principal,
        }
        capability_id = digest(base_payload)
        payload = dict(base_payload)
        payload["capability_id"] = capability_id
        payload_bytes = canonicalize(payload)
        envelope = canonicalize(
            {
                "algorithm": "Ed25519",
                "key_id": key_id(self.__private_key.public_key()),
                "payload": payload,
                "signature": sign(self.__private_key, CAPABILITY_DOMAIN, payload_bytes),
            }
        )
        return IssueResult(envelope=envelope, decision=decision, capability_id=capability_id)
