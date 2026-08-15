import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "orchestrator/tcb"))

from check_gates import check_gates


def test_gate_results_reject_unbound_subject(tmp_path, monkeypatch):
    monkeypatch.chdir(ROOT)
    document = {
        "schema_version": 1,
        "subject": "attacker-controlled-subject",
        "results": [
            {"gate_id": gate, "status": "PASS", "evidence": "forged"}
            for gate in ["ROOT_INTEGRITY", "STATE_INTEGRITY", "PATCH_SCOPE", "F00_HELLO_WORLD"]
        ],
    }
    path = tmp_path / "gates.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(RuntimeError):
        check_gates(path)


def test_gate_results_require_exact_subject(tmp_path, monkeypatch):
    monkeypatch.chdir(ROOT)
    subject = "a" * 64
    document = {
        "schema_version": 1,
        "subject": subject,
        "results": [
            {"gate_id": gate, "status": "PASS", "evidence": "real"}
            for gate in ["ROOT_INTEGRITY", "STATE_INTEGRITY", "PATCH_SCOPE", "F00_HELLO_WORLD"]
        ],
    }
    path = tmp_path / "gates.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    assert check_gates(path, subject) is True
    with pytest.raises(RuntimeError):
        check_gates(path, "b" * 64)
