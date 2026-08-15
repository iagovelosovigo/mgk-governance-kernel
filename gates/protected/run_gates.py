import argparse
import json
import os
import tempfile
from pathlib import Path

from test_f00 import test_hello_world
from test_invariants import test_root_of_trust, test_state_json


def _result(gate_id, function):
    try:
        function()
        return {"gate_id": gate_id, "status": "PASS", "evidence": "deterministic check passed"}
    except BaseException as exc:
        detail = f"{type(exc).__name__}: {exc}"[:1000]
        return {"gate_id": gate_id, "status": "FAIL", "evidence": detail}


def run(output_file, subject, patch_scope_pass):
    results = [
        {
            "gate_id": "PATCH_SCOPE",
            "status": "PASS" if patch_scope_pass else "FAIL",
            "evidence": "verify_patch.py passed" if patch_scope_pass else "patch scope not attested",
        },
        _result("ROOT_INTEGRITY", test_root_of_trust),
        _result("STATE_INTEGRITY", test_state_json),
        _result("F00_HELLO_WORLD", test_hello_world),
    ]
    document = {"schema_version": 1, "subject": subject, "results": results}
    output = Path(output_file)
    output.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix="gates.", suffix=".tmp", dir=output.parent)
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
    return all(item["status"] == "PASS" for item in results)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--patch-scope-pass", action="store_true")
    parser.add_argument("--subject", required=True)
    parser.add_argument("output_file")
    arguments = parser.parse_args()
    raise SystemExit(
        0 if run(arguments.output_file, arguments.subject, arguments.patch_scope_pass) else 1
    )
