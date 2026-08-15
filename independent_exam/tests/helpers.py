from __future__ import annotations

import copy
import hashlib
import threading
from typing import Any, Mapping


class Counter:
    def __init__(self) -> None:
        self.value = 0
        self._lock = threading.Lock()

    def operation(self) -> int:
        with self._lock:
            self.value += 1
            return self.value


def assert_denied(result: Mapping[str, Any], counter: Counter) -> None:
    assert result.get("executed") is False, result
    assert isinstance(result.get("code"), str) and result["code"], result
    assert counter.value == 0, "protected operation ran despite denial"


def assert_authorized(result: Mapping[str, Any], counter: Counter) -> None:
    assert result.get("executed") is True, result
    assert counter.value == 1, "authorized operation did not run exactly once"


def mutated_capability(harness: Any, capability: Any, key: str, value: Any) -> Any:
    claims = copy.deepcopy(dict(harness.claims(capability)))
    claims[key] = value
    return harness.assemble(claims, harness.signature(capability))


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

