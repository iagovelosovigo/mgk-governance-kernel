"""ROLLBACK_CONFINEMENT probe for create_bound rollback unlink (mutmut_105 / _107).

Mutation: os.unlink(name, dir_fd=parent)  ->  os.unlink(name, dir_fd=None) / (name, )

A rollback unlink must stay anchored to the authorized parent directory fd and
must never resolve through the process CWD (which may lie outside the resource
root). A controlled short-write failure triggers the rollback path.
"""
import hashlib
import json
import os
import stat as stat_mod
import tempfile
from pathlib import Path

from mgk import ResourceGuard

tmp = Path(tempfile.mkdtemp())
root = tmp / "root"
(root / "workspace").mkdir(parents=True)
cwd_dir = tmp / "cwd"
(cwd_dir / "workspace").mkdir(parents=True)
(cwd_dir / "workspace" / "x.txt").write_bytes(b"DECOY")
os.chdir(cwd_dir)

guard = ResourceGuard(root)
data = b"payload"
sha = hashlib.sha256(data).hexdigest()
binding = guard.bind_absent("workspace/x.txt", sha, len(data))

real_write = os.write
calls = {"n": 0}


def failing_write(fd, buf):
    calls["n"] += 1
    if calls["n"] == 1:
        raise OSError("injected short-write failure")
    return real_write(fd, buf)


os.write = failing_write
try:
    try:
        guard.create_bound(binding, data)
        outcome = "NO_ERROR"
    except Exception as exc:  # noqa: BLE001 - rollback trigger injection
        outcome = f"{type(exc).__name__}:{exc}"
finally:
    os.write = real_write

resource_file_exists = (root / "workspace" / "x.txt").exists()
decoy_exists = (cwd_dir / "workspace" / "x.txt").exists()
decoy_mode = stat_mod.S_IMODE(os.stat(cwd_dir / "workspace" / "x.txt").st_mode) if decoy_exists else None

print(
    "RESULT_JSON="
    + json.dumps(
        {
            "outcome": outcome,
            "resource_file_after_rollback_exists": resource_file_exists,
            "cwd_decoy_after_rollback_exists": decoy_exists,
            "cwd_decoy_mode": decoy_mode,
            "rollback_confined": (not resource_file_exists) and decoy_exists,
        }
    )
)