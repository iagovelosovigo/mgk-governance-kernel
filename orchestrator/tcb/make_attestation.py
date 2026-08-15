import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

from check_candidate import check_candidate
from check_gates import check_gates
from core import verify_state


def _git(*args):
    return subprocess.run(
        ["git", *args], check=True, capture_output=True, text=True
    ).stdout.strip()


def _sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def make_attestation(metadata_file, patch_file, pre_gates_file, final_gates_file, output_file):
    metadata = check_candidate(metadata_file, patch_file, require_base_head=False)
    commit_sha = _git("rev-parse", "HEAD")
    parent_sha = _git("rev-parse", "HEAD^")
    tree_sha = _git("rev-parse", "HEAD^{tree}")
    check_gates(pre_gates_file, metadata["PATCH_SHA256"])
    check_gates(final_gates_file, commit_sha)
    if parent_sha != metadata["BASE_SHA"]:
        raise RuntimeError("Candidate commit is not a single child of the verified base")
    if _git("status", "--porcelain", "--untracked-files=all"):
        raise RuntimeError("Candidate workspace is not clean")
    state = verify_state()
    if state["phase"] != "DONE":
        raise RuntimeError("Candidate state is not DONE")
    document = {
        "schema_version": 1,
        "phase": metadata["PHASE"],
        "base_sha": metadata["BASE_SHA"],
        "patch_sha256": metadata["PATCH_SHA256"],
        "candidate_commit_sha": commit_sha,
        "candidate_tree_sha": tree_sha,
        "state_sha256": state["hash"],
        "pre_gate_results_sha256": _sha256(Path(pre_gates_file)),
        "final_gate_results_sha256": _sha256(Path(final_gates_file)),
        "workflow_run_id": os.environ.get("GITHUB_RUN_ID", "local"),
        "workflow_run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT", "local"),
        "human_authorization_required": True,
        "automated_merge": False,
    }
    output = Path(output_file)
    output.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix="attestation.", suffix=".tmp", dir=output.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(document, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, output)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return document


if __name__ == "__main__":
    try:
        if len(sys.argv) != 6:
            raise RuntimeError(
                "Usage: make_attestation.py <metadata> <patch> <pre-gates> <final-gates> <output>"
            )
        make_attestation(*sys.argv[1:])
        print("Candidate attestation created.")
    except Exception as exc:
        print(exc)
        raise SystemExit(1)
