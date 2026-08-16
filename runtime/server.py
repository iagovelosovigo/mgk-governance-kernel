"""Runtime server lifecycle: start/stop/status/doctor/test."""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
import urllib.request
from pathlib import Path
from typing import Any

from .config import RuntimeConfig
from .flight import FlightRecorder
from .sandbox import ACTUATOR_ACTIONS
from .workspace import Workspace


def _pid_path(config: RuntimeConfig) -> Path:
    return config.workdir / ".mgk" / "runtime.pid"


def _port_path(config: RuntimeConfig) -> Path:
    return config.workdir / ".mgk" / "runtime.port"


def start(config: RuntimeConfig, foreground: bool = False) -> dict[str, Any]:
    if foreground:
        from .web import make_server

        workspace = Workspace(config)
        bundle = workspace.create_runtime()
        server = make_server(bundle, config.host, config.port)
        print(
            json.dumps(
                {"status": "started", "host": config.host, "port": config.port, "mode": "foreground"}
            )
        )
        server.serve_forever()
        return {"status": "stopped"}

    workspace = Workspace(config)
    workspace.root.mkdir(parents=True, exist_ok=True)
    command = [
        sys.executable,
        "-m",
        "runtime.server",
        "serve",
        "--workdir",
        str(config.workdir),
        "--host",
        config.host,
        "--port",
        str(config.port),
        "--ttl",
        str(config.ttl_seconds),
    ]
    repo_root = Path(__file__).resolve().parent.parent
    env = dict(os.environ)
    python_path = str(repo_root / "src")
    python_path += os.pathsep + str(repo_root)
    env["PYTHONPATH"] = (
        python_path + os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else python_path
    )
    log_path = config.workdir / ".mgk" / "runtime.log"
    descriptor = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    process = subprocess.Popen(
        command,
        start_new_session=True,
        stdin=subprocess.DEVNULL,
        stdout=descriptor,
        stderr=descriptor,
        close_fds=True,
        env=env,
    )
    os.close(descriptor)
    _pid_path(config).write_text(str(process.pid) + "\n")
    _port_path(config).write_text(str(config.port) + "\n")
    deadline = time.time() + 15
    health = None
    while time.time() < deadline:
        current = status(config)
        if current.get("status") == "running":
            health = current
            break
        time.sleep(0.25)
    if health is None or health.get("status") != "running":
        raise RuntimeError("runtime failed to become healthy")
    return health


def stop(config: RuntimeConfig) -> dict[str, Any]:
    pid_file = _pid_path(config)
    if not pid_file.exists():
        return {"status": "not_running"}
    pid = int(pid_file.read_text().strip())
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    deadline = time.time() + 10
    while time.time() < deadline:
        try:
            os.kill(pid, 0)
            time.sleep(0.2)
        except ProcessLookupError:
            break
    pid_file.unlink(missing_ok=True)
    _port_path(config).unlink(missing_ok=True)
    return {"status": "stopped"}


def status(config: RuntimeConfig) -> dict[str, Any]:
    pid_file = _pid_path(config)
    port_file = _port_path(config)
    if not pid_file.exists() or not port_file.exists():
        return {"status": "not_running"}
    port = int(port_file.read_text().strip())
    try:
        with urllib.request.urlopen(
            f"http://127.0.0.1:{port}/api/health", timeout=3
        ) as response:
            health = json.loads(response.read().decode("utf-8"))
    except Exception:
        return {"status": "not_running", "port": port}
    pid = int(pid_file.read_text().strip())
    payload = {"status": "running", "pid": pid, "host": "127.0.0.1", "port": port}
    for key, value in health.items():
        if key != "status":
            payload[key] = value
    return payload


def doctor(config: RuntimeConfig) -> dict[str, Any]:
    findings: list[str] = []
    checks: dict[str, str] = {}
    workspace = Workspace(config)
    checks["workspace_initialized"] = "PASS" if workspace.initialized else "FAIL"
    if not workspace.initialized:
        findings.append("runtime workspace is not initialized; run mgk start first")
        return {"status": "FAIL", "checks": checks, "findings": findings}
    try:
        bundle = workspace.create_runtime()
        checks["epoch_initialized"] = "PASS"
    except Exception as exc:
        checks["epoch_initialized"] = "FAIL"
        findings.append(f"runtime state error: {exc}")
        return {"status": "FAIL", "checks": checks, "findings": findings}
    try:
        bundle.audit.verify_integrity()
        checks["audit_integrity"] = "PASS"
    except Exception as exc:
        checks["audit_integrity"] = "FAIL"
        findings.append(f"audit integrity: {exc}")
    try:
        bundle.failures.verify_integrity()
        checks["failure_ledger_integrity"] = "PASS"
    except Exception as exc:
        checks["failure_ledger_integrity"] = "FAIL"
        findings.append(f"failure ledger integrity: {exc}")
    try:
        bundle.flight.verify_integrity()
        checks["flight_integrity"] = "PASS"
    except Exception as exc:
        checks["flight_integrity"] = "FAIL"
        findings.append(f"flight integrity: {exc}")
    try:
        bundle.state.integrity_check()
        checks["state_integrity"] = "PASS"
    except Exception as exc:
        checks["state_integrity"] = "FAIL"
        findings.append(f"state integrity: {exc}")
    checks["actuator_registry"] = "PASS" if len(ACTUATOR_ACTIONS) == 5 else "FAIL"
    if len(ACTUATOR_ACTIONS) != 5:
        findings.append("actuator registry does not contain the closed five-actuator set")
    status_value = "PASS" if not findings else "FAIL"
    return {"status": status_value, "checks": checks, "findings": findings}


def test(config: RuntimeConfig) -> dict[str, Any]:
    results = {
        "h14_proposal_is_not_authority": _test_proposal_not_authority(config),
    }
    passed = all(results.values())
    return {"status": "PASS" if passed else "FAIL", "results": results}


def _test_proposal_not_authority(config: RuntimeConfig) -> bool:
    workspace = Workspace(config)
    bundle = workspace.create_runtime()
    proposal = {
        "request_id": "probe-proposal-not-authority",
        "principal": "planner",
        "audience": "executor",
        "action": "sandbox.read_file",
        "resource": "files/probe.txt",
        "parameters": {},
    }
    from mgk.crypto import b64u_encode

    (bundle.workspace.files_root / "probe.txt").write_bytes(b"probe\n")
    decision = bundle.pipeline.propose(proposal)
    allowed = decision.state.value == "ALLOW" and decision.executed
    unauthorized = {
        "request_id": "probe-unauthorized",
        "principal": "planner",
        "audience": "executor",
        "action": "sandbox.write_file",
        "resource": "../escape.txt",
        "parameters": {"content_b64": b64u_encode(b"x")},
    }
    denied = bundle.pipeline.propose(unauthorized).state.value == "DENY"
    return allowed and denied


def serve(config: RuntimeConfig) -> None:
    from .web import make_server

    workspace = Workspace(config)
    bundle = workspace.create_runtime()
    server = make_server(bundle, config.host, config.port)
    try:
        server.serve_forever()
    finally:
        server.server_close()


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(prog="mgk-runtime")
    subparsers = parser.add_subparsers(dest="command", required=True)
    start_parser = subparsers.add_parser("start")
    start_parser.add_argument("--workdir", required=True)
    start_parser.add_argument("--host", default="127.0.0.1")
    start_parser.add_argument("--port", type=int, default=8787)
    start_parser.add_argument("--ttl", type=int, default=60)
    start_parser.add_argument("--foreground", action="store_true")
    stop_parser = subparsers.add_parser("stop")
    stop_parser.add_argument("--workdir", required=True)
    status_parser = subparsers.add_parser("status")
    status_parser.add_argument("--workdir", required=True)
    doctor_parser = subparsers.add_parser("doctor")
    doctor_parser.add_argument("--workdir", required=True)
    test_parser = subparsers.add_parser("test")
    test_parser.add_argument("--workdir", required=True)
    serve_parser = subparsers.add_parser("serve")
    serve_parser.add_argument("--workdir", required=True)
    serve_parser.add_argument("--host", default="127.0.0.1")
    serve_parser.add_argument("--port", type=int, default=8787)
    serve_parser.add_argument("--ttl", type=int, default=60)
    arguments = parser.parse_args(argv)
    config = RuntimeConfig.from_workdir(
        arguments.workdir,
        port=getattr(arguments, "port", 8787),
        host=getattr(arguments, "host", "127.0.0.1"),
        ttl_seconds=getattr(arguments, "ttl", 60),
    )
    if arguments.command == "start":
        result = start(config, foreground=arguments.foreground)
    elif arguments.command == "stop":
        result = stop(config)
    elif arguments.command == "status":
        result = status(config)
    elif arguments.command == "doctor":
        result = doctor(config)
    elif arguments.command == "test":
        result = test(config)
    elif arguments.command == "serve":
        serve(config)
        return 0
    else:
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result.get("status") in {"PASS", "running", "stopped", "not_running", "started"} else 1


if __name__ == "__main__":
    raise SystemExit(main())