import hashlib
import os
import re
import stat
from pathlib import Path, PurePosixPath

MANIFEST_PATH = Path("contracts/ROOT_MANIFEST.sha256")
ANCHOR_ENV = "MGK_ROOT_MANIFEST_SHA256"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
REQUIRED_PROTECTED_PATHS = {
    ".github/workflows/bootstrap-core.yml",
    "contracts/FUNCTIONAL_ACCEPTANCE.yaml",
    "contracts/INVARIANTS.yaml",
    "contracts/PHASES.yaml",
    "contracts/ROOT_OF_TRUST",
    "gates/protected/run_gates.py",
    "gates/protected/test_f00.py",
    "gates/protected/test_invariants.py",
    "orchestrator/tcb/check_candidate.py",
    "orchestrator/tcb/check_gates.py",
    "orchestrator/tcb/contracts.py",
    "orchestrator/tcb/core.py",
    "orchestrator/tcb/make_attestation.py",
    "orchestrator/tcb/trust.py",
    "orchestrator/tcb/verify_patch.py",
}


def sha256_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _load_manifest():
    if MANIFEST_PATH.is_symlink() or not MANIFEST_PATH.is_file():
        raise RuntimeError("Root manifest missing or not a regular file")
    entries = {}
    previous = None
    for number, line in enumerate(MANIFEST_PATH.read_text(encoding="ascii").splitlines(), 1):
        parts = line.split("  ", 1)
        if len(parts) != 2 or not _SHA256.fullmatch(parts[0]):
            raise RuntimeError(f"Malformed root manifest line {number}")
        digest, relative = parts
        path = PurePosixPath(relative)
        if path.is_absolute() or not path.parts or any(part in {"", ".", ".."} for part in path.parts):
            raise RuntimeError(f"Unsafe root manifest path: {relative}")
        if relative in entries or (previous is not None and relative <= previous):
            raise RuntimeError("Root manifest paths must be unique and sorted")
        entries[relative] = digest
        previous = relative
    if set(entries) != REQUIRED_PROTECTED_PATHS:
        missing = sorted(REQUIRED_PROTECTED_PATHS - set(entries))
        extra = sorted(set(entries) - REQUIRED_PROTECTED_PATHS)
        raise RuntimeError(f"Root manifest coverage mismatch; missing={missing}, extra={extra}")
    return entries


def verify_protected_tree():
    anchor = os.environ.get(ANCHOR_ENV, "")
    if not _SHA256.fullmatch(anchor):
        raise RuntimeError(f"{ANCHOR_ENV} is missing or invalid")
    actual_manifest_hash = sha256_file(MANIFEST_PATH)
    if actual_manifest_hash != anchor:
        raise RuntimeError(
            f"Root manifest hash mismatch: expected {anchor}, got {actual_manifest_hash}"
        )
    for relative, expected in _load_manifest().items():
        path = Path(relative)
        if path.is_symlink() or not path.exists():
            raise RuntimeError(f"Protected path missing or symlinked: {relative}")
        mode = path.stat().st_mode
        if not stat.S_ISREG(mode):
            raise RuntimeError(f"Protected path is not a regular file: {relative}")
        actual = sha256_file(path)
        if actual != expected:
            raise RuntimeError(
                f"Protected path hash mismatch for {relative}: expected {expected}, got {actual}"
            )
    return True


if __name__ == "__main__":
    try:
        verify_protected_tree()
        print("Protected tree verified.")
    except Exception as exc:
        print(exc)
        raise SystemExit(1)
