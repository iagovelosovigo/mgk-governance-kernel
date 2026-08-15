import fnmatch
import os
import stat
import subprocess
import sys
from pathlib import Path, PurePosixPath

from contracts import load_phase
from core import verify_state
from trust import verify_protected_tree

MAX_PATCH_BYTES = 1024 * 1024
MAX_CHANGED_PATHS = 32


def _run(command, check=True, **kwargs):
    return subprocess.run(command, check=check, **kwargs)


def _safe_path(relative):
    path = PurePosixPath(relative)
    return (
        bool(path.parts)
        and not path.is_absolute()
        and "\\" not in relative
        and all(part not in {"", ".", ".."} for part in path.parts)
    )


def _allowed(relative, patterns):
    return any(fnmatch.fnmatchcase(relative, pattern) for pattern in patterns)


def _staged_mode(relative):
    result = _run(
        ["git", "ls-files", "--stage", "-z", "--", relative],
        capture_output=True,
    ).stdout
    if not result:
        return None
    records = [record for record in result.split(b"\0") if record]
    if len(records) != 1:
        raise RuntimeError(f"Ambiguous staged path: {relative}")
    header, staged_path = records[0].split(b"\t", 1)
    if staged_path.decode("utf-8", "strict") != relative:
        raise RuntimeError(f"Staged path mismatch: {relative}")
    mode = header.split(b" ", 1)[0].decode("ascii")
    return mode


def verify_patch(patch_file):
    verify_protected_tree()
    state = verify_state()
    phase = load_phase(state["phase"])
    patterns = phase["allowed_paths"]

    patch = Path(patch_file)
    if patch.is_symlink() or not patch.is_file():
        raise RuntimeError("Patch is missing or not a regular file")
    patch_mode = patch.stat().st_mode
    if not stat.S_ISREG(patch_mode) or patch.stat().st_size <= 0:
        raise RuntimeError("Patch is empty or not regular")
    if patch.stat().st_size > MAX_PATCH_BYTES:
        raise RuntimeError("Patch exceeds size limit")
    if _run(["git", "diff", "--cached", "--quiet"], check=False).returncode != 0:
        raise RuntimeError("Git index is not clean before patch verification")

    try:
        check = subprocess.run(
            ["git", "apply", "--check", "--whitespace=error-all", os.fspath(patch)],
            capture_output=True,
        )
        if check.returncode != 0:
            raise RuntimeError(f"Patch not applicable: {check.stderr.decode('utf-8', 'replace')}")
        _run(["git", "apply", "--cached", "--whitespace=error-all", os.fspath(patch)])
        raw = _run(
            ["git", "diff", "--cached", "--name-only", "-z", "--no-renames", "HEAD"],
            capture_output=True,
        ).stdout
        paths = [item.decode("utf-8", "strict") for item in raw.split(b"\0") if item]
        if not paths or len(paths) > MAX_CHANGED_PATHS or len(paths) != len(set(paths)):
            raise RuntimeError("Invalid changed-path set")
        for relative in paths:
            if not _safe_path(relative) or not _allowed(relative, patterns):
                raise RuntimeError(f"Path not allowed by phase {state['phase']}: {relative}")
            mode = _staged_mode(relative)
            if mode is not None and mode != "100644":
                raise RuntimeError(f"Forbidden staged file mode {mode}: {relative}")
    finally:
        subprocess.run(
            ["git", "reset", "--mixed", "--quiet", "HEAD"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    return True


if __name__ == "__main__":
    try:
        if len(sys.argv) != 2:
            raise RuntimeError("Usage: verify_patch.py <patch_file>")
        verify_patch(sys.argv[1])
        print("Patch verification passed.")
    except Exception as exc:
        print(exc)
        raise SystemExit(1)
