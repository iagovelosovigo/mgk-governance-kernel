import hashlib
import json
import os
import tempfile
from pathlib import Path

from trust import verify_protected_tree

STATE_PATH = Path("orchestrator/tcb/state.json")
STATE_KEYS = {"version", "phase", "attempts", "phases_done", "hash"}


def compute_state_hash(state):
    state_copy = {key: value for key, value in state.items() if key != "hash"}
    canonical = json.dumps(
        state_copy,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")
    return hashlib.sha256(canonical).hexdigest()


def verify_state():
    state = json.loads(STATE_PATH.read_text(encoding="utf-8"))
    if set(state) != STATE_KEYS:
        raise RuntimeError(f"Invalid state schema: {sorted(state)}")
    if type(state["version"]) is not int or state["version"] != 1:
        raise RuntimeError("Invalid state version")
    if type(state["attempts"]) is not int or state["attempts"] < 0:
        raise RuntimeError("Invalid state attempts")
    if not isinstance(state["phases_done"], list) or any(
        not isinstance(item, str) for item in state["phases_done"]
    ):
        raise RuntimeError("Invalid phases_done")
    if len(state["phases_done"]) != len(set(state["phases_done"])):
        raise RuntimeError("Duplicate phase in phases_done")
    expected_done = {"F00": [], "DONE": ["F00"]}
    if state["phase"] not in expected_done or state["phases_done"] != expected_done[state["phase"]]:
        raise RuntimeError("Invalid phase transition state")
    if not isinstance(state["hash"], str) or state["hash"] != compute_state_hash(state):
        raise RuntimeError("State hash mismatch or missing hash")
    return state


def _atomic_write_state(state):
    STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix="state.", suffix=".tmp", dir=STATE_PATH.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(state, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, STATE_PATH)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def advance_state():
    verify_protected_tree()
    state = verify_state()
    if state["phase"] != "F00":
        raise RuntimeError(f"Cannot advance phase {state['phase']}")
    state["phases_done"] = ["F00"]
    state["phase"] = "DONE"
    state["attempts"] = 0
    state["hash"] = compute_state_hash(state)
    _atomic_write_state(state)
    return verify_state()


if __name__ == "__main__":
    import sys

    try:
        if sys.argv[1:] != ["--advance"]:
            raise RuntimeError("Usage: core.py --advance")
        advance_state()
        print("State advanced.")
    except Exception as exc:
        print(exc)
        raise SystemExit(1)
