"""Verify the Phase 13 release freeze signature for the security-mutation-adequacy campaign.

Recomputes the manifest payload from the recorded file list + digests, then
checks the Ed25519 signature against the recorded signer public key. Read-only.
"""

import hashlib
import json
import sys
from pathlib import Path

from mgk.crypto import verify

REPO = Path(__file__).resolve().parents[2]
FREEZE = REPO / "evidence" / "v0.2.0" / "release" / "freeze-security-mutation-adequacy.json"


def main() -> int:
    data = json.loads(FREEZE.read_text())
    manifest = data["manifest"]
    failures = []

    # 1. every recorded file must exist and match its recorded sha256
    for entry in manifest["files"]:
        p = REPO / entry["path"]
        if not p.exists():
            failures.append(f"missing {entry['path']}")
            continue
        digest = hashlib.sha256(p.read_bytes()).hexdigest()
        if digest != entry["sha256"]:
            failures.append(f"sha256 mismatch {entry['path']}: recorded {entry['sha256'][:12]} got {digest[:12]}")

    # 2. re-serialize the manifest exactly as signed (sort_keys, separators)
    payload = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()

    # 3. verify signature against recorded public key bytes
    pub_bytes = bytes.fromhex(data["signer_public_key_bytes"])
    from mgk.crypto import load_public_key
    pub = load_public_key(pub_bytes)
    try:
        verify(pub, b"MGK-FREEZE-V1\x00", payload, data["signature"])
        sig_ok = True
    except Exception as exc:
        sig_ok = False
        failures.append(f"signature verification failed: {exc}")

    print(json.dumps({
        "verified": not failures,
        "files_checked": len(manifest["files"]),
        "signature_valid": sig_ok,
        "signer": data["signer_public_key"],
        "git_commit": manifest["git"]["commit"],
        "git_tree": manifest["git"]["tree"],
        "failures": failures,
    }, indent=1))
    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(main())