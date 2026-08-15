"""Signed-checkpoint, hash-chained audit and failure ledgers."""

from __future__ import annotations

import fcntl
import hashlib
import os
import tempfile
import threading
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .canonical import canonicalize, parse_canonical
from .crypto import AUDIT_DOMAIN, key_id, sign, verify
from .errors import AuditIntegrityError

GENESIS_HASH = "0" * 64


class AuditLedger:
    def __init__(
        self,
        ledger_path: str | Path,
        checkpoint_path: str | Path,
        public_key: Ed25519PublicKey,
        private_key: Ed25519PrivateKey | None = None,
    ):
        self.ledger_path = Path(ledger_path)
        self.checkpoint_path = Path(checkpoint_path)
        self.public_key = public_key
        self.private_key = private_key
        self._lock = threading.RLock()
        self.ledger_path.parent.mkdir(parents=True, exist_ok=True)
        self.checkpoint_path.parent.mkdir(parents=True, exist_ok=True)
        if not self.ledger_path.exists() and not self.checkpoint_path.exists():
            if private_key is None:
                raise AuditIntegrityError("cannot initialize a verify-only ledger")
            self.ledger_path.touch(mode=0o600, exist_ok=False)
            self._write_checkpoint(0, GENESIS_HASH, 0)
        elif not self.ledger_path.exists() or not self.checkpoint_path.exists():
            raise AuditIntegrityError("partial audit ledger state")
        self.verify_integrity()

    def _checkpoint_document(self, count: int, head_hash: str, updated_at: int) -> dict[str, Any]:
        return {
            "count": count,
            "head_hash": head_hash,
            "key_id": key_id(self.public_key),
            "schema": "mgk-ledger-checkpoint/v1",
            "updated_at": updated_at,
        }

    def _write_checkpoint(self, count: int, head_hash: str, updated_at: int) -> None:
        if self.private_key is None:
            raise AuditIntegrityError("ledger is verify-only")
        document = self._checkpoint_document(count, head_hash, updated_at)
        envelope = canonicalize(
            {
                "document": document,
                "signature": sign(self.private_key, AUDIT_DOMAIN, canonicalize(document)),
            }
        )
        descriptor, temporary = tempfile.mkstemp(
            prefix=self.checkpoint_path.name + ".",
            suffix=".tmp",
            dir=self.checkpoint_path.parent,
        )
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(envelope)
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

    def _load_checkpoint(self) -> dict[str, Any]:
        try:
            raw = self.checkpoint_path.read_bytes()
            if not raw.endswith(b"\n"):
                raise AuditIntegrityError("checkpoint newline missing")
            envelope = parse_canonical(raw[:-1])
        except AuditIntegrityError:
            raise
        except Exception as exc:
            raise AuditIntegrityError(f"cannot parse ledger checkpoint: {exc}") from exc
        if type(envelope) is not dict or set(envelope) != {"document", "signature"}:
            raise AuditIntegrityError("invalid checkpoint envelope")
        document = envelope["document"]
        required = {"count", "head_hash", "key_id", "schema", "updated_at"}
        if type(document) is not dict or set(document) != required:
            raise AuditIntegrityError("invalid checkpoint schema")
        if document["schema"] != "mgk-ledger-checkpoint/v1":
            raise AuditIntegrityError("unsupported checkpoint schema")
        if document["key_id"] != key_id(self.public_key):
            raise AuditIntegrityError("checkpoint signer mismatch")
        if type(document["count"]) is not int or document["count"] < 0:
            raise AuditIntegrityError("invalid checkpoint count")
        if type(document["updated_at"]) is not int or document["updated_at"] < 0:
            raise AuditIntegrityError("invalid checkpoint time")
        if type(document["head_hash"]) is not str or len(document["head_hash"]) != 64:
            raise AuditIntegrityError("invalid checkpoint head")
        try:
            verify(
                self.public_key,
                AUDIT_DOMAIN,
                canonicalize(document),
                envelope["signature"],
            )
        except Exception as exc:
            raise AuditIntegrityError(f"checkpoint signature failed: {exc}") from exc
        return document

    def _scan(self) -> tuple[int, str]:
        count = 0
        previous = GENESIS_HASH
        try:
            with self.ledger_path.open("rb") as stream:
                for line in stream:
                    if not line.endswith(b"\n"):
                        raise AuditIntegrityError("unterminated ledger record")
                    record = parse_canonical(line[:-1])
                    required = {"data", "event_hash", "event_type", "prev_hash", "seq", "timestamp"}
                    if type(record) is not dict or set(record) != required:
                        raise AuditIntegrityError("invalid ledger record schema")
                    event_hash = record.pop("event_hash")
                    expected = hashlib.sha256(canonicalize(record)).hexdigest()
                    if event_hash != expected:
                        raise AuditIntegrityError("ledger event hash mismatch")
                    if record["seq"] != count + 1 or record["prev_hash"] != previous:
                        raise AuditIntegrityError("ledger chain discontinuity")
                    if type(record["timestamp"]) is not int or record["timestamp"] < 0:
                        raise AuditIntegrityError("invalid ledger timestamp")
                    if type(record["event_type"]) is not str or not record["event_type"]:
                        raise AuditIntegrityError("invalid ledger event type")
                    previous = event_hash
                    count += 1
        except AuditIntegrityError:
            raise
        except Exception as exc:
            raise AuditIntegrityError(f"cannot scan ledger: {exc}") from exc
        return count, previous

    def verify_integrity(self) -> tuple[int, str]:
        with self._lock:
            checkpoint = self._load_checkpoint()
            count, head = self._scan()
            if checkpoint["count"] != count or checkpoint["head_hash"] != head:
                raise AuditIntegrityError("ledger does not match signed checkpoint")
            return count, head

    def append(self, event_type: str, data: dict[str, Any], timestamp: int) -> str:
        if self.private_key is None:
            raise AuditIntegrityError("ledger is verify-only")
        if type(event_type) is not str or not event_type or type(data) is not dict:
            raise AuditIntegrityError("invalid ledger append request")
        if type(timestamp) is not int or timestamp < 0:
            raise AuditIntegrityError("invalid ledger append timestamp")
        with self._lock:
            with self.ledger_path.open("ab+") as stream:
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
                    self._write_checkpoint(count + 1, event_hash, timestamp)
                    return event_hash
                finally:
                    fcntl.flock(stream.fileno(), fcntl.LOCK_UN)


class FailureLedger(AuditLedger):
    def record(self, data: dict[str, Any], timestamp: int) -> str:
        return self.append("FAILURE", data, timestamp)
