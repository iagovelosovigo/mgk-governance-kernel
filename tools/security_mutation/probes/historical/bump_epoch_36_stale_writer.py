"""EPOCH_MONOTONICITY probe for mgk.state.xǁSecurityStateǁbump_epoch__mutmut_36.

Mutation: if row is None or self._decode_epoch(row[0]) != current:
          if row is None and self._decode_epoch(row[0]) != current:

A stale writer whose start-of-call epoch view is behind the committed epoch must
be rejected; the authorization epoch must never regress.
"""
import json
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from mgk.errors import EpochError
from mgk.state import SecurityState


class StaleWriter(SecurityState):
    """Simulates a writer whose start-of-call view predates concurrent bumps."""

    def __init__(self, path, public_key, stale_epoch):
        super().__init__(path, public_key)
        self._stale = stale_epoch

    def current_epoch(self):
        return self._stale


key = Ed25519PrivateKey.generate()
tmp = Path(tempfile.mkdtemp())
db = tmp / "state.sqlite"

writer = SecurityState(db, key.public_key())
writer.initialize_epoch(1, key)
writer.bump_epoch(key)
writer.bump_epoch(key)
committed_before = writer.current_epoch()

stale = StaleWriter(db, key.public_key(), stale_epoch=1)
try:
    result = stale.bump_epoch(key)
    stale_result = f"accepted:{result}"
except EpochError as exc:
    stale_result = f"rejected:{exc}"

reader = SecurityState(db, key.public_key())
try:
    committed_after = reader.current_epoch()
except EpochError as exc:
    committed_after = f"unreadable:{exc}"
print(
    "RESULT_JSON="
    + json.dumps(
        {
            "committed_before": committed_before,
            "committed_after": committed_after,
            "stale_writer_outcome": stale_result,
            "epoch_monotonic": committed_before == 3
            and committed_after == 3,
        }
    )
)