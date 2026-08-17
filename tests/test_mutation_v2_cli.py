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
    assert captured.out == (
        '{\n'
        '  "allowed_control_executed": true,\n'
        '  "forbidden_capability_issued": false,\n'
        '  "h14_forbidden_executions": 0,\n'
        '  "result": "PASS"\n'
        '}\n'
    )


def test_cli_main_h14_smoke_without_workdir_uses_tempdir(capsys):
    rc = main(["h14-smoke"])
    assert rc == 0
    captured = capsys.readouterr()
    assert json.loads(captured.out)["result"] == "PASS"


def test_cli_main_rejects_unknown_command():
    import argparse

    try:
        main(["unknown-command"])
    except SystemExit as exc:
        assert exc.code == 2
        return
    raise AssertionError("expected SystemExit(2)")


def test_cli_main_rejects_missing_command(capsys):
    try:
        main([])
    except SystemExit as exc:
        assert exc.code == 2
        captured = capsys.readouterr()
        assert "mgk" in captured.err
        return
    raise AssertionError("expected SystemExit(2)")


def test_cli_main_status_not_running_returns_zero(tmp_path):
    rc = main(["status", "--workdir", str(tmp_path)])
    assert rc == 0


def test_cli_main_stop_not_running_returns_zero(tmp_path):
    rc = main(["stop", "--workdir", str(tmp_path)])
    assert rc == 0


def test_cli_main_doctor_uninitialized_returns_one(tmp_path):
    rc = main(["doctor", "--workdir", str(tmp_path)])
    assert rc == 1


def _init_workspace(tmp_path):
    from runtime.config import RuntimeConfig
    from runtime.workspace import Workspace

    config = RuntimeConfig.from_workdir(tmp_path / "rt")
    Workspace(config).create_runtime()
    return str(tmp_path / "rt")


def test_cli_main_doctor_pass_after_init(tmp_path):
    workdir = _init_workspace(tmp_path)
    rc = main(["doctor", "--workdir", workdir])
    assert rc == 0


def test_cli_main_test_pass_after_init(tmp_path):
    workdir = _init_workspace(tmp_path)
    rc = main(["test", "--workdir", workdir])
    assert rc == 0


def test_cli_main_doctor_detects_tampered_ledger(tmp_path):
    from runtime.config import RuntimeConfig
    from runtime.workspace import Workspace

    config = RuntimeConfig.from_workdir(tmp_path / "rt")
    bundle = Workspace(config).create_runtime()
    with bundle.audit.ledger_path.open("ab") as stream:
        stream.write(b'{"tampered": true}\n')
    rc = main(["doctor", "--workdir", str(tmp_path / "rt")])
    assert rc == 1


def test_cli_main_runtime_commands_require_workdir():
    for command in ("status", "stop", "doctor", "test"):
        try:
            main([command])
        except SystemExit as exc:
            assert exc.code == 2
        else:
            raise AssertionError(f"expected SystemExit(2) for {command}")


def test_cli_main_start_requires_workdir_exact(capsys):
    try:
        main(["start"])
    except SystemExit as exc:
        assert exc.code == 2
        captured = capsys.readouterr()
        assert "usage: mgk" in captured.err
        assert "required: --workdir" in captured.err
        return
    raise AssertionError("expected SystemExit(2)")


def test_system_clock_now_returns_epoch_second():
    value = SystemClock().now()
    assert isinstance(value, int)
    assert value > 1_500_000_000