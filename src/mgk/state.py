"""Transactional authorization epoch and replay state."""

from __future__ import annotations

import sqlite3
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .canonical import canonicalize, parse_canonical
from .crypto import EPOCH_DOMAIN, key_id, sign, verify
from .errors import EpochError, ReplayError, StateIntegrityError

SCHEMA_VERSION = 1


class SecurityState:
    def __init__(
        self,
        path: str | Path,
        epoch_public_key: Ed25519PublicKey,
        expected_minimum_epoch: int = 1,
    ):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.epoch_public_key = epoch_public_key
        if type(expected_minimum_epoch) is not int or expected_minimum_epoch < 1:
            raise ValueError("expected_minimum_epoch must be a positive integer")
        self.expected_minimum_epoch = expected_minimum_epoch
        self._ensure_schema()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=30000")
        return connection

    def _ensure_schema(self) -> None:
        try:
            with self._connect() as connection:
                connection.executescript(
                    """
                    CREATE TABLE IF NOT EXISTS metadata (
                        key TEXT PRIMARY KEY,
                        value BLOB NOT NULL
                    );
                    CREATE TABLE IF NOT EXISTS consumed_nonces (
                        nonce TEXT PRIMARY KEY,
                        capability_id TEXT NOT NULL,
                        consumed_at INTEGER NOT NULL
                    );
                    """
                )
                row = connection.execute(
                    "SELECT value FROM metadata WHERE key='schema_version'"
                ).fetchone()
                if row is None:
                    connection.execute(
                        "INSERT INTO metadata(key,value) VALUES('schema_version',?)",
                        (str(SCHEMA_VERSION).encode("ascii"),),
                    )
                elif row[0] != str(SCHEMA_VERSION).encode("ascii"):
                    raise StateIntegrityError("security state schema mismatch")
        except sqlite3.DatabaseError as exc:
            raise StateIntegrityError(f"security state initialization failed: {exc}") from exc

    def integrity_check(self) -> None:
        try:
            with self.path.open("rb") as stream:
                if stream.read(16) != b"SQLite format 3\x00":
                    raise StateIntegrityError("security state file header is invalid")
        except OSError as exc:
            raise StateIntegrityError(f"security state file is unreadable: {exc}") from exc
        try:
            with self._connect() as connection:
                result = connection.execute("PRAGMA quick_check").fetchone()
                if result != ("ok",):
                    raise StateIntegrityError(f"SQLite integrity check failed: {result}")
                schema = connection.execute(
                    "SELECT value FROM metadata WHERE key='schema_version'"
                ).fetchone()
                if schema != (str(SCHEMA_VERSION).encode("ascii"),):
                    raise StateIntegrityError("security state schema missing or invalid")
        except sqlite3.DatabaseError as exc:
            raise StateIntegrityError(f"security state is unreadable: {exc}") from exc

    def initialize_epoch(self, epoch: int, signer: Ed25519PrivateKey) -> None:
        if type(epoch) is not int or epoch < 1:
            raise ValueError("epoch must be a positive integer")
        document = {"epoch": epoch, "key_id": key_id(signer.public_key()), "schema": "mgk-epoch/v1"}
        encoded = canonicalize(document)
        envelope = canonicalize({"document": document, "signature": sign(signer, EPOCH_DOMAIN, encoded)})
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                existing = connection.execute(
                    "SELECT value FROM metadata WHERE key='epoch_envelope'"
                ).fetchone()
                if existing is not None:
                    raise EpochError("authorization epoch is already initialized")
                connection.execute(
                    "INSERT INTO metadata(key,value) VALUES('epoch_envelope',?)", (envelope,)
                )
                connection.execute("COMMIT")
        except (sqlite3.DatabaseError, StateIntegrityError) as exc:
            raise StateIntegrityError(f"cannot initialize epoch: {exc}") from exc

    def _decode_epoch(self, envelope: bytes) -> int:
        value = parse_canonical(bytes(envelope))
        if type(value) is not dict or set(value) != {"document", "signature"}:
            raise EpochError("invalid epoch envelope")
        document = value["document"]
        if type(document) is not dict or set(document) != {"epoch", "key_id", "schema"}:
            raise EpochError("invalid epoch document")
        if document["schema"] != "mgk-epoch/v1":
            raise EpochError("unsupported epoch schema")
        if document["key_id"] != key_id(self.epoch_public_key):
            raise EpochError("epoch signer mismatch")
        verify(
            self.epoch_public_key,
            EPOCH_DOMAIN,
            canonicalize(document),
            value["signature"],
        )
        epoch = document["epoch"]
        if type(epoch) is not int or epoch < self.expected_minimum_epoch:
            raise EpochError("authorization epoch rollback or invalid epoch")
        return epoch

    def current_epoch(self) -> int:
        self.integrity_check()
        try:
            with self._connect() as connection:
                row = connection.execute(
                    "SELECT value FROM metadata WHERE key='epoch_envelope'"
                ).fetchone()
        except sqlite3.DatabaseError as exc:
            raise StateIntegrityError(f"cannot read epoch: {exc}") from exc
        if row is None:
            raise EpochError("authorization epoch is not initialized")
        return self._decode_epoch(row[0])

    def bump_epoch(self, signer: Ed25519PrivateKey) -> int:
        current = self.current_epoch()
        next_epoch = current + 1
        document = {
            "epoch": next_epoch,
            "key_id": key_id(signer.public_key()),
            "schema": "mgk-epoch/v1",
        }
        envelope = canonicalize(
            {
                "document": document,
                "signature": sign(signer, EPOCH_DOMAIN, canonicalize(document)),
            }
        )
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute(
                    "SELECT value FROM metadata WHERE key='epoch_envelope'"
                ).fetchone()
                if row is None or self._decode_epoch(row[0]) != current:
                    connection.execute("ROLLBACK")
                    raise EpochError("epoch changed concurrently")
                connection.execute(
                    "UPDATE metadata SET value=? WHERE key='epoch_envelope'", (envelope,)
                )
                connection.execute("COMMIT")
        except sqlite3.DatabaseError as exc:
            raise StateIntegrityError(f"cannot bump epoch: {exc}") from exc
        self.expected_minimum_epoch = next_epoch
        return next_epoch

    def consume_nonce(self, nonce: str, capability_id: str, consumed_at: int) -> None:
        if type(nonce) is not str or type(capability_id) is not str or type(consumed_at) is not int:
            raise ReplayError("invalid nonce consumption request")
        self.integrity_check()
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                connection.execute(
                    "INSERT INTO consumed_nonces(nonce,capability_id,consumed_at) VALUES(?,?,?)",
                    (nonce, capability_id, consumed_at),
                )
                connection.execute("COMMIT")
        except sqlite3.IntegrityError as exc:
            raise ReplayError("nonce was already consumed") from exc
        except sqlite3.DatabaseError as exc:
            raise StateIntegrityError(f"cannot consume nonce: {exc}") from exc

    def nonce_count(self) -> int:
        self.integrity_check()
        try:
            with self._connect() as connection:
                return int(connection.execute("SELECT COUNT(*) FROM consumed_nonces").fetchone()[0])
        except sqlite3.DatabaseError as exc:
            raise StateIntegrityError(f"cannot count nonces: {exc}") from exc
