"""Runtime ledger: durable record of proposals, decisions, and human actions."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

from mgk.canonical import canonicalize, parse_canonical
from mgk.errors import StateIntegrityError

SCHEMA_VERSION = 1


class RuntimeLedger:
    """SQLite-backed proposal/decision/human-action store for the web UI.

    Every row is mirrored to the flight recorder by the decision pipeline;
    the SQLite store is a queryable index, not a source of trust.
    """

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._ensure_schema()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute("PRAGMA busy_timeout=30000")
        return connection

    def _ensure_schema(self) -> None:
        try:
            with self._connect() as connection:
                connection.executescript(
                    """
                    CREATE TABLE IF NOT EXISTS proposals (
                        request_id TEXT PRIMARY KEY,
                        principal TEXT NOT NULL,
                        audience TEXT NOT NULL,
                        action TEXT NOT NULL,
                        resource TEXT NOT NULL,
                        parameters BLOB NOT NULL,
                        request_digest TEXT NOT NULL,
                        created_at INTEGER NOT NULL
                    );
                    CREATE TABLE IF NOT EXISTS decisions (
                        decision_id TEXT PRIMARY KEY,
                        request_id TEXT NOT NULL,
                        state TEXT NOT NULL,
                        reason_codes BLOB NOT NULL,
                        capability_id TEXT,
                        executed INTEGER NOT NULL DEFAULT 0,
                        output_digest TEXT,
                        flight_hash TEXT NOT NULL,
                        created_at INTEGER NOT NULL,
                        UNIQUE(request_id)
                    );
                    CREATE TABLE IF NOT EXISTS human_actions (
                        action_id TEXT PRIMARY KEY,
                        request_id TEXT NOT NULL,
                        operator TEXT NOT NULL,
                        decision TEXT NOT NULL,
                        signature TEXT NOT NULL,
                        flight_hash TEXT NOT NULL,
                        created_at INTEGER NOT NULL
                    );
                    CREATE TABLE IF NOT EXISTS metadata (
                        key TEXT PRIMARY KEY,
                        value BLOB NOT NULL
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
                    raise StateIntegrityError("runtime ledger schema mismatch")
        except sqlite3.DatabaseError as exc:
            raise StateIntegrityError(f"runtime ledger initialization failed: {exc}") from exc

    def store_proposal(self, request: dict[str, Any], request_digest: str, created_at: int) -> None:
        parameters = canonicalize(request["parameters"])
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                connection.execute(
                    "INSERT INTO proposals(request_id,principal,audience,action,resource,parameters,request_digest,created_at) "
                    "VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(request_id) DO NOTHING",
                    (
                        request["request_id"],
                        request["principal"],
                        request["audience"],
                        request["action"],
                        request["resource"],
                        parameters,
                        request_digest,
                        created_at,
                    ),
                )
                connection.execute("COMMIT")
        except sqlite3.DatabaseError as exc:
            raise StateIntegrityError(f"cannot store proposal: {exc}") from exc

    def store_decision(
        self,
        decision_id: str,
        request_id: str,
        state: str,
        reason_codes: list[str],
        capability_id: str | None,
        executed: bool,
        output_digest: str | None,
        flight_hash: str,
        created_at: int,
    ) -> None:
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                connection.execute(
                    "INSERT INTO decisions(decision_id,request_id,state,reason_codes,capability_id,executed,output_digest,flight_hash,created_at) "
                    "VALUES(?,?,?,?,?,?,?,?,?) "
                    "ON CONFLICT(request_id) DO UPDATE SET "
                    "decision_id=excluded.decision_id,state=excluded.state,reason_codes=excluded.reason_codes,"
                    "capability_id=excluded.capability_id,executed=excluded.executed,"
                    "output_digest=excluded.output_digest,flight_hash=excluded.flight_hash,"
                    "created_at=excluded.created_at",
                    (
                        decision_id,
                        request_id,
                        state,
                        canonicalize(reason_codes),
                        capability_id,
                        1 if executed else 0,
                        output_digest,
                        flight_hash,
                        created_at,
                    ),
                )
                connection.execute("COMMIT")
        except sqlite3.DatabaseError as exc:
            raise StateIntegrityError(f"cannot store decision: {exc}") from exc

    def store_human_action(
        self,
        action_id: str,
        request_id: str,
        operator: str,
        decision: str,
        signature: str,
        flight_hash: str,
        created_at: int,
    ) -> None:
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                connection.execute(
                    "INSERT INTO human_actions(action_id,request_id,operator,decision,signature,flight_hash,created_at) "
                    "VALUES(?,?,?,?,?,?,?)",
                    (action_id, request_id, operator, decision, signature, flight_hash, created_at),
                )
                connection.execute("COMMIT")
        except sqlite3.DatabaseError as exc:
            raise StateIntegrityError(f"cannot store human action: {exc}") from exc

    def proposal(self, request_id: str) -> dict[str, Any] | None:
        try:
            with self._connect() as connection:
                row = connection.execute(
                    "SELECT request_id,principal,audience,action,resource,parameters,request_digest,created_at "
                    "FROM proposals WHERE request_id=?",
                    (request_id,),
                ).fetchone()
        except sqlite3.DatabaseError as exc:
            raise StateIntegrityError(f"cannot read proposal: {exc}") from exc
        if row is None:
            return None
        return {
            "request_id": row[0],
            "principal": row[1],
            "audience": row[2],
            "action": row[3],
            "resource": row[4],
            "parameters": parse_canonical(row[5]),
            "request_digest": row[6],
            "created_at": row[7],
        }

    def proposals(self) -> list[dict[str, Any]]:
        try:
            with self._connect() as connection:
                rows = connection.execute(
                    "SELECT request_id,principal,audience,action,resource,parameters,request_digest,created_at "
                    "FROM proposals ORDER BY created_at DESC"
                ).fetchall()
        except sqlite3.DatabaseError as exc:
            raise StateIntegrityError(f"cannot read proposals: {exc}") from exc
        return [
            {
                "request_id": row[0],
                "principal": row[1],
                "audience": row[2],
                "action": row[3],
                "resource": row[4],
                "parameters": parse_canonical(row[5]),
                "request_digest": row[6],
                "created_at": row[7],
            }
            for row in rows
        ]

    def decisions(self) -> list[dict[str, Any]]:
        try:
            with self._connect() as connection:
                rows = connection.execute(
                    "SELECT decision_id,request_id,state,reason_codes,capability_id,executed,output_digest,flight_hash,created_at "
                    "FROM decisions ORDER BY created_at DESC"
                ).fetchall()
        except sqlite3.DatabaseError as exc:
            raise StateIntegrityError(f"cannot read decisions: {exc}") from exc
        return [
            {
                "decision_id": row[0],
                "request_id": row[1],
                "state": row[2],
                "reason_codes": parse_canonical(row[3]),
                "capability_id": row[4],
                "executed": bool(row[5]),
                "output_digest": row[6],
                "flight_hash": row[7],
                "created_at": row[8],
            }
            for row in rows
        ]

    def human_actions(self) -> list[dict[str, Any]]:
        try:
            with self._connect() as connection:
                rows = connection.execute(
                    "SELECT action_id,request_id,operator,decision,signature,flight_hash,created_at "
                    "FROM human_actions ORDER BY created_at DESC"
                ).fetchall()
        except sqlite3.DatabaseError as exc:
            raise StateIntegrityError(f"cannot read human actions: {exc}") from exc
        return [
            {
                "action_id": row[0],
                "request_id": row[1],
                "operator": row[2],
                "decision": row[3],
                "signature": row[4],
                "flight_hash": row[5],
                "created_at": row[6],
            }
            for row in rows
        ]