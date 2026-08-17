"""RESOURCE_PERMISSIONS probe for create_bound file mode (mutmut_68 / _70).

Mutation: os.open(name, flags, 0o600, dir_fd=parent)
          -> os.open(name, flags, dir_fd=parent)        (mode omitted -> 0o777 & ~umask)
          -> os.open(name, flags, 385, dir_fd=parent)   (0o600 -> 0o601)

The created resource must stay 0600 under an unrestricted (umask 0) environment.
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

old_umask = os.umask(0)
try:
    guard = ResourceGuard(root)
    data = b"x"
    sha = hashlib.sha256(data).hexdigest()
    binding = guard.bind_absent("workspace/p.txt", sha, len(data))
    guard.create_bound(binding, data)
finally:
    os.umask(old_umask)

mode = stat_mod.S_IMODE(os.stat(root / "workspace" / "p.txt").st_mode)
print(
    "RESULT_JSON="
    + json.dumps(
        {
            "file_mode_octal": oct(mode),
            "protected_0600": mode == 0o600,
        }
    )
)