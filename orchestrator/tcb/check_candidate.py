import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

_SHA = re.compile(r"^[0-9a-f]{40,64}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def _sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def check_candidate(metadata_file, patch_file, require_base_head=True):
    metadata = json.loads(Path(metadata_file).read_text(encoding="utf-8"))
    if set(metadata) != {"BASE_SHA", "PATCH_SHA256", "PHASE"}:
        raise RuntimeError("Invalid build metadata schema")
    if not _SHA.fullmatch(metadata["BASE_SHA"]) or not _SHA256.fullmatch(metadata["PATCH_SHA256"]):
        raise RuntimeError("Invalid digest in build metadata")
    if metadata["PHASE"] != "F00":
        raise RuntimeError("Unexpected phase in build metadata")
    head = subprocess.run(
        ["git", "rev-parse", "HEAD"], check=True, capture_output=True, text=True
    ).stdout.strip()
    if require_base_head and metadata["BASE_SHA"] != head:
        raise RuntimeError(f"Base mismatch: expected {metadata['BASE_SHA']}, got {head}")
    actual_patch = _sha256(Path(patch_file))
    if metadata["PATCH_SHA256"] != actual_patch:
        raise RuntimeError(
            f"Patch digest mismatch: expected {metadata['PATCH_SHA256']}, got {actual_patch}"
        )
    return metadata


if __name__ == "__main__":
    try:
        if len(sys.argv) != 3:
            raise RuntimeError("Usage: check_candidate.py <metadata.json> <patch>")
        check_candidate(sys.argv[1], sys.argv[2])
        print("Candidate metadata verified.")
    except Exception as exc:
        print(exc)
        raise SystemExit(1)
