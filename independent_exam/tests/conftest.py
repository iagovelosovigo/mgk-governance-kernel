from __future__ import annotations

import importlib
import os
import sys
from pathlib import Path

import pytest

EXAM_ROOT = Path(__file__).resolve().parents[1]
if str(EXAM_ROOT) not in sys.path:
    sys.path.insert(0, str(EXAM_ROOT))

from api_contract import FrozenClock


@pytest.fixture
def clock() -> FrozenClock:
    return FrozenClock()


@pytest.fixture
def harness(tmp_path: Path, clock: FrozenClock):
    module_name = os.environ.get("MGK_CANDIDATE_ADAPTER", "candidate_adapter")
    try:
        adapter = importlib.import_module(module_name)
    except Exception as exc:
        pytest.fail(f"candidate adapter {module_name!r} is not importable: {exc}")
    factory = getattr(adapter, "create_harness", None)
    if not callable(factory):
        pytest.fail(f"{module_name!r} does not export callable create_harness")
    instance = factory(tmp_path, clock)
    if instance is None:
        pytest.fail("create_harness returned None")
    return instance

