"""Flight recorder: append-only, hash-chained event log for the runtime."""

from __future__ import annotations

import fcntl
import hashlib
import os
import tempfile
from pathlib import Path
from typing import Any

from mgk.canonical import canonicalize, parse_canonical
from mgk.errors import AuditIntegrityError

GENESIS_HASH = "0" * 64


class FlightRecorder:
    """Ordered, tamper-evident record of every runtime event.

    Each record is hash-chained to the previous and a checkpoint pins the
    head. ``verify_integrity`` rescans the chain and compares it to the
    checkpoint so any truncation or mutation is detected.
    """

    def __init__(self, path: str | Path, checkpoint_path: str | Path):
        self.path = Path(path)
        self.checkpoint_path = Path(checkpoint_path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists() and not self.checkpoint_path.exists():
            self.path.touch(mode=0o600, exist_ok=False)
            self._write_checkpoint(0, GENESIS_HASH)
        elif not self.path.exists() or not self.checkpoint_path.exists():
            raise AuditIntegrityError("partial flight recorder state")
        self.verify_integrity()

    def _write_checkpoint(self, count: int, head_hash: str) -> None:
        document = canonicalize({"count": count, "head_hash": head_hash})
        descriptor, temporary = tempfile.mkstemp(
            prefix=self.checkpoint_path.name + ".",
            suffix=".tmp",
            dir=self.checkpoint_path.parent,
        )
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(document)
                stream.write(b"\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.checkpoint_path)
            directory = os.open(self.checkpoint_path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

    def _load_checkpoint(self) -> tuple[int, str]:
        try:
            raw = self.checkpoint_path.read_bytes()
            if not raw.endswith(b"\n"):
                raise AuditIntegrityError("checkpoint newline missing")
            value = parse_canonical(raw[:-1])
        except AuditIntegrityError:
            raise
        except Exception as exc:
            raise AuditIntegrityError(f"cannot parse flight checkpoint: {exc}") from exc
        if type(value) is not dict or set(value) != {"count", "head_hash"}:
            raise AuditIntegrityError("invalid flight checkpoint")
        count, head = value["count"], value["head_hash"]
        if type(count) is not int or count < 0:
            raise AuditIntegrityError("invalid flight checkpoint count")
        if type(head) is not str or len(head) != 64:
            raise AuditIntegrityError("invalid flight checkpoint head")
        return count, head

    def _scan(self) -> tuple[int, str]:
        count = 0
        previous = GENESIS_HASH
        try:
            with self.path.open("rb") as stream:
                for line in stream:
                    if not line.endswith(b"\n"):
                        raise AuditIntegrityError("unterminated flight record")
                    record = parse_canonical(line[:-1])
                    required = {"data", "event_hash", "event_type", "prev_hash", "seq", "timestamp"}
                    if type(record) is not dict or set(record) != required:
                        raise AuditIntegrityError("invalid flight record schema")
                    event_hash = record.pop("event_hash")
                    expected = hashlib.sha256(canonicalize(record)).hexdigest()
                    if event_hash != expected:
                        raise AuditIntegrityError("flight event hash mismatch")
                    if record["seq"] != count + 1 or record["prev_hash"] != previous:
                        raise AuditIntegrityError("flight chain discontinuity")
                    if type(record["timestamp"]) is not int or record["timestamp"] < 0:
                        raise AuditIntegrityError("invalid flight timestamp")
                    previous = event_hash
                    count += 1
        except AuditIntegrityError:
            raise
        except Exception as exc:
            raise AuditIntegrityError(f"cannot scan flight recorder: {exc}") from exc
        return count, previous

    def verify_integrity(self) -> tuple[int, str]:
        count, head = self._scan()
        checkpoint = self._load_checkpoint()
        if checkpoint != (count, head):
            raise AuditIntegrityError("flight recorder does not match checkpoint")
        return count, head

    def append(self, event_type: str, data: dict[str, Any], timestamp: int) -> str:
        if type(event_type) is not str or not event_type or type(data) is not dict:
            raise AuditIntegrityError("invalid flight append request")
        if type(timestamp) is not int or timestamp < 0:
            raise AuditIntegrityError("invalid flight timestamp")
        with self.path.open("ab+") as stream:
            fcntl.flock(stream.fileno(), fcntl.LOCK_EX)
            try:
                count, head = self.verify_integrity()
                body = {
                    "data": data,
                    "event_type": event_type,
                    "prev_hash": head,
                    "seq": count + 1,
                    "timestamp": timestamp,
                }
                event_hash = hashlib.sha256(canonicalize(body)).hexdigest()
                record = dict(body)
                record["event_hash"] = event_hash
                stream.write(canonicalize(record) + b"\n")
                stream.flush()
                os.fsync(stream.fileno())
                self._write_checkpoint(count + 1, event_hash)
                return event_hash
            finally:
                fcntl.flock(stream.fileno(), fcntl.LOCK_UN)