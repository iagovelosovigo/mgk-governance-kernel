"""RESOURCE_IDENTITY probe for mgk.resource.xǁResourceGuardǁremove_created__mutmut_42.

Mutation: len(data) != post_size or sha != digest  ->  ... and ...

remove_created must refuse to roll back a file whose content does not match the
authorized digest, even when the byte length is identical.
"""
import hashlib
import json
import tempfile
from pathlib import Path

from mgk import ResourceGuard

tmp = Path(tempfile.mkdtemp())
root = tmp / "root"
(root / "workspace").mkdir(parents=True)

guard = ResourceGuard(root)
data = b"AAAA"
sha = hashlib.sha256(data).hexdigest()
binding = guard.bind_absent("workspace/r.txt", sha, len(data))
guard.create_bound(binding, data)

(root / "workspace" / "r.txt").write_bytes(b"BBBB")

result = guard.remove_created(binding, sha)
file_exists = (root / "workspace" / "r.txt").exists()

print(
    "RESULT_JSON="
    + json.dumps(
        {
            "remove_created_result": bool(result),
            "tampered_file_exists": file_exists,
            "digest_identity_enforced": (not result) and file_exists,
        }
    )
)