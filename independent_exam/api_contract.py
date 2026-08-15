"""Contrato de adaptación del examen independiente MGK v0.1.0.

El candidate adapter debe implementar este protocolo sin que los tests necesiten
conocer la estructura interna del kernel. Los métodos son síncronos para hacer
deterministas las pruebas; el adaptador puede encapsular una implementación
asíncrona.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol, Sequence


SAXP_OUTCOMES = frozenset({"TEN_XEITO", "REQUIRE_XEITO", "NON_TEN_XEITO"})


@dataclass
class FrozenClock:
    """Reloj controlable. El candidato debe consultar ``now`` en cada uso."""

    now: int = 1_700_000_000

    def advance(self, seconds: int) -> None:
        if seconds < 0:
            raise ValueError("clock cannot move backwards")
        self.now += seconds


Request = Mapping[str, Any]
Result = Mapping[str, Any]
Operation = Callable[[], Any]
Hook = Callable[[], None]


class Harness(Protocol):
    """Frontera observable exigida al candidato.

    Resultados de ``verify``: ``authorized: bool`` y ``code: str``.
    Resultados de ``execute``: ``executed: bool`` y ``code: str``.
    Ningún error controlado puede escapar de ``verify``/``execute``; debe
    convertirse en denegación con evidencia. Sólo ``BaseException`` de proceso
    queda fuera de este contrato.
    """

    def canonicalize(self, value: Any) -> bytes: ...

    def propose(self, request: Request) -> Mapping[str, Any]: ...

    def evaluate(
        self, proposal: Mapping[str, Any], context: Mapping[str, Any] | None = None
    ) -> Result: ...

    def issue(
        self,
        request: Request,
        *,
        scope: Sequence[str] | None = None,
        issued_at: int | None = None,
        expires_at: int | None = None,
        nonce: str | None = None,
        epoch: int | None = None,
    ) -> Any: ...

    def verify(self, capability: Any, request: Request) -> Result: ...

    def execute(
        self,
        capability: Any,
        request: Request,
        operation: Operation,
        *,
        before_commit: Hook | None = None,
    ) -> Result: ...

    def rotate_epoch(self) -> int: ...

    def current_epoch(self) -> int: ...

    def export_capability(self, capability: Any) -> bytes: ...

    def import_capability(self, wire: bytes) -> Any: ...

    def claims(self, capability: Any) -> Mapping[str, Any]: ...

    def signature(self, capability: Any) -> bytes: ...

    def assemble(self, claims: Mapping[str, Any], signature: bytes) -> Any: ...

    def authority_public_key(self) -> bytes: ...

    def planner_view(self) -> Any: ...

    def audit_events(self) -> list[Mapping[str, Any]]: ...

    def failure_events(self) -> list[Mapping[str, Any]]: ...

    def audit_integrity(self) -> Result: ...

    def corrupt_audit(self) -> None: ...


class CandidateAdapter(Protocol):
    def create_harness(self, root: Path, clock: FrozenClock) -> Harness: ...


def request(
    *,
    action: str = "kv.write",
    resource: str = "urn:mgk:test:alpha",
    payload: Any = None,
    resource_digest: str | None = None,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "action": action,
        "resource": resource,
        "payload": {} if payload is None else payload,
    }
    if resource_digest is not None:
        result["resource_digest"] = resource_digest
    return result

