#!/usr/bin/env python3
"""Run the protected exam against an independently installed candidate."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import sys
import tarfile
import tempfile
import xml.etree.ElementTree as ET
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def safe_relative(name: str) -> Path:
    pure = PurePosixPath(name)
    if pure.is_absolute() or ".." in pure.parts:
        raise ValueError(f"unsafe archive member: {name}")
    return Path(*pure.parts)


def unpack(source: Path, destination: Path) -> str:
    if source.is_dir():
        shutil.copytree(source, destination, dirs_exist_ok=True)
        return tree_digest(destination)
    source_hash = sha256(source)
    if zipfile.is_zipfile(source):
        with zipfile.ZipFile(source) as archive:
            for info in archive.infolist():
                target = destination / safe_relative(info.filename)
                mode = info.external_attr >> 16
                if mode & 0o170000 == 0o120000:
                    raise ValueError(f"archive symlink rejected: {info.filename}")
                if info.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                else:
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with archive.open(info) as src, target.open("wb") as dst:
                        shutil.copyfileobj(src, dst)
    elif tarfile.is_tarfile(source):
        with tarfile.open(source) as archive:
            for member in archive.getmembers():
                if member.issym() or member.islnk():
                    raise ValueError(f"archive link rejected: {member.name}")
                target = destination / safe_relative(member.name)
                if member.isdir():
                    target.mkdir(parents=True, exist_ok=True)
                elif member.isfile():
                    target.parent.mkdir(parents=True, exist_ok=True)
                    src = archive.extractfile(member)
                    if src is None:
                        raise ValueError(f"unreadable member: {member.name}")
                    with src, target.open("wb") as dst:
                        shutil.copyfileobj(src, dst)
    else:
        raise ValueError("candidate source must be a directory, ZIP, or tar archive")
    return source_hash


def tree_digest(root: Path) -> str:
    h = hashlib.sha256()
    for path in sorted(root.rglob("*")):
        if not path.is_file() or "__pycache__" in path.parts or path.suffix == ".pyc":
            continue
        relative = path.relative_to(root).as_posix().encode()
        h.update(len(relative).to_bytes(8, "big"))
        h.update(relative)
        data = path.read_bytes()
        h.update(len(data).to_bytes(8, "big"))
        h.update(data)
    return h.hexdigest()


def candidate_root(unpacked: Path) -> Path:
    direct = unpacked / "pyproject.toml"
    if direct.is_file():
        return unpacked
    matches = list(unpacked.glob("*/pyproject.toml"))
    if len(matches) != 1:
        raise ValueError("archive must contain exactly one Python project")
    return matches[0].parent


def junit_counts(path: Path) -> dict[str, int | str]:
    root = ET.parse(path).getroot()
    suites = [root] if root.tag == "testsuite" else list(root.findall("testsuite"))
    counts = {
        key: sum(int(suite.attrib.get(key, 0)) for suite in suites)
        for key in ("tests", "failures", "errors", "skipped")
    }
    counts["status"] = "PASS" if not counts["failures"] and not counts["errors"] and not counts["skipped"] and counts["tests"] else "FAIL"
    return counts


def run(command: list[str], *, cwd: Path, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, cwd=cwd, env=env, text=True, capture_output=True, timeout=600)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--label", choices=("A", "B"), required=True)
    parser.add_argument("--adapter", default="candidate_adapter")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()

    report: dict[str, object] = {
        "schema_version": "mgk.clean-install.v1",
        "label": args.label,
        "status": "FAIL",
    }
    with tempfile.TemporaryDirectory(prefix=f"mgk-clean-{args.label}-") as raw:
        work = Path(raw)
        source_dir = work / "source"
        source_dir.mkdir()
        try:
            report["source_sha256"] = unpack(args.source.resolve(), source_dir)
            project = candidate_root(source_dir)
            report["source_tree_sha256"] = tree_digest(project)
            venv = work / "venv"
            subprocess.run([sys.executable, "-m", "venv", str(venv)], check=True, timeout=120)
            py = venv / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
            env = os.environ.copy()
            env.update({"PYTHONHASHSEED": "0", "PYTHONNOUSERSITE": "1", "SOURCE_DATE_EPOCH": "1700000000"})
            installed = run(
                [str(py), "-m", "pip", "install", "--no-index", str(project)],
                cwd=work,
                env=env,
            )
            report["install_exit_code"] = installed.returncode
            report["install_output_sha256"] = hashlib.sha256((installed.stdout + installed.stderr).encode()).hexdigest()
            if installed.returncode:
                raise RuntimeError("offline installation failed")

            wheel_dir = work / "wheel"
            wheel_dir.mkdir()
            wheel = run(
                [str(py), "-m", "pip", "wheel", "--no-index", "--no-deps", "-w", str(wheel_dir), str(project)],
                cwd=work,
                env=env,
            )
            report["wheel_exit_code"] = wheel.returncode
            wheels = list(wheel_dir.glob("*.whl"))
            report["wheel_sha256"] = sha256(wheels[0]) if wheel.returncode == 0 and len(wheels) == 1 else None

            site = run(
                [str(py), "-c", "import site; print(site.getsitepackages()[0])"],
                cwd=work,
                env=env,
            ).stdout.strip()
            test_env = env | {
                "MGK_CANDIDATE_ADAPTER": args.adapter,
                "PYTHONPATH": os.pathsep.join([site, str(ROOT)]),
            }
            junit = work / "junit.xml"
            tested = run(
                [sys.executable, "-m", "pytest", "-q", str(ROOT / "tests"), f"--junitxml={junit}"],
                cwd=work,
                env=test_env,
            )
            report["test_exit_code"] = tested.returncode
            report["test_output_sha256"] = hashlib.sha256((tested.stdout + tested.stderr).encode()).hexdigest()
            report["tests"] = junit_counts(junit) if junit.is_file() else {"status": "FAIL"}

            h14_junit = work / "h14.xml"
            h14 = run(
                [sys.executable, "-m", "pytest", "-q", str(ROOT / "tests"), "-m", "h14", f"--junitxml={h14_junit}"],
                cwd=work,
                env=test_env,
            )
            report["h14_exit_code"] = h14.returncode
            report["h14"] = junit_counts(h14_junit) if h14_junit.is_file() else {"status": "FAIL"}
            if (
                tested.returncode == 0
                and h14.returncode == 0
                and report["wheel_sha256"]
                and report["tests"]["status"] == "PASS"
                and report["h14"]["status"] == "PASS"
            ):
                report["status"] = "PASS"
        except Exception as exc:
            report["error"] = f"{type(exc).__name__}: {exc}"

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(report["status"])
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())

