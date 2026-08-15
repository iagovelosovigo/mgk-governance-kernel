import sys
from pathlib import Path

TCB_DIR = Path(__file__).resolve().parents[2] / "orchestrator" / "tcb"
sys.path.insert(0, str(TCB_DIR))

from core import verify_state
from trust import verify_protected_tree


def test_root_of_trust():
    assert verify_protected_tree() is True


def test_state_json():
    state = verify_state()
    assert state["phase"] in {"F00", "DONE"}
    assert state["phases_done"] == ([] if state["phase"] == "F00" else ["F00"])
