from __future__ import annotations

import json

from mgk import SystemClock
from mgk.cli import _safe_context, h14_smoke, main
from mgk.models import SAXPContext


def test_cli_safe_context_exact_fields():
    request = None
    context = _safe_context(request)
    assert isinstance(context, SAXPContext)
    assert context.coherence_delta == 100
    assert context.systemic_pressure == 10
    assert context.threshold_k == 100
    assert context.sentidino == 9000
    assert context.information_complete is True
    assert context.critical_uncertainty is False
    assert context.control_risk is False
    assert context.ethical_constraints_satisfied is True
    assert context.to_payload() == {
        "coherence_delta": 100,
        "control_risk": False,
        "critical_uncertainty": False,
        "ethical_constraints_satisfied": True,
        "information_complete": True,
        "sentidino": 9000,
        "systemic_pressure": 10,
        "threshold_k": 100,
    }


def test_cli_h14_smoke_exact_result_and_side_effects(tmp_path):
    result = h14_smoke(tmp_path)
    assert result == {
        "allowed_control_executed": True,
        "forbidden_capability_issued": False,
        "h14_forbidden_executions": 0,
        "result": "PASS",
    }
    allowed = tmp_path / "resources" / "workspace" / "allowed.txt"
    assert allowed.read_bytes() == b"MGK authority boundary\n"
    assert (tmp_path / "resources" / "workspace").is_dir()
    assert (tmp_path / "security.sqlite").exists()
    assert (tmp_path / "audit.jsonl").exists()
    assert (tmp_path / "audit.checkpoint.json").exists()
    assert (tmp_path / "failures.jsonl").exists()
    assert (tmp_path / "failures.checkpoint.json").exists()


def test_cli_h14_smoke_is_deterministic(tmp_path):
    first = h14_smoke(tmp_path / "run-a")
    second = h14_smoke(tmp_path / "run-b")
    assert first == second


def test_cli_main_h14_smoke_returns_zero_and_prints_json(capsys, tmp_path):
    rc = main(["h14-smoke", "--workdir", str(tmp_path)])
    assert rc == 0
    captured = capsys.readouterr()
    assert json.loads(captured.out) == {
        "allowed_control_executed": True,
        "forbidden_capability_issued": False,
        "h14_forbidden_executions": 0,
        "result": "PASS",
    }
    assert captured.out.strip().endswith("}")


def test_cli_main_rejects_unknown_command():
    import argparse

    try:
        main(["unknown-command"])
    except SystemExit as exc:
        assert exc.code == 2
        return
    raise AssertionError("expected SystemExit(2)")


def test_cli_main_rejects_missing_command():
    try:
        main([])
    except SystemExit as exc:
        assert exc.code == 2
        return
    raise AssertionError("expected SystemExit(2)")


def test_system_clock_now_returns_epoch_second():
    value = SystemClock().now()
    assert isinstance(value, int)
    assert value > 1_500_000_000