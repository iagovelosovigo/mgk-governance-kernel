from __future__ import annotations

import sqlite3

import pytest

from mgk import SecurityState
from mgk.canonical import parse_canonical
from mgk.crypto import generate_private_key
from mgk.errors import EpochError, ReplayError, StateIntegrityError


def make_state(path):
    key = generate_private_key()
    return SecurityState(path, key.public_key(), 1), key


def test_state_default_minimum_epoch_is_one(tmp_path):
    key = generate_private_key()
    state = SecurityState(tmp_path / "state.sqlite", key.public_key())
    assert state.expected_minimum_epoch == 1


def test_state_rejects_invalid_minimum_epoch(tmp_path):
    key = generate_private_key()
    for bad in (0, -1, True, 1.5, "1"):
        with pytest.raises(ValueError, match="^expected_minimum_epoch must be a positive integer$"):
            SecurityState(tmp_path / "s.sqlite", key.public_key(), bad)


def test_state_initialize_epoch_exact_envelope(tmp_path):
    state, key = make_state(tmp_path / "state.sqlite")
    state.initialize_epoch(1, key)
    connection = sqlite3.connect(state.path)
    raw = connection.execute("SELECT value FROM metadata WHERE key='epoch_envelope'").fetchone()[0]
    connection.close()
    envelope = parse_canonical(raw)
    assert set(envelope) == {"document", "signature"}
    document = envelope["document"]
    assert set(document) == {"epoch", "key_id", "schema"}
    assert document["epoch"] == 1
    assert document["schema"] == "mgk-epoch/v1"
    assert isinstance(envelope["signature"], str)
    assert state.current_epoch() == 1


def test_state_initialize_epoch_validates_epoch(tmp_path):
    state, key = make_state(tmp_path / "state.sqlite")
    for bad in (0, -1, True, 1.5, "1"):
        with pytest.raises(ValueError, match="^epoch must be a positive integer$"):
            state.initialize_epoch(bad, key)


def test_state_initialize_epoch_twice_is_rejected(tmp_path):
    state, key = make_state(tmp_path / "state.sqlite")
    state.initialize_epoch(1, key)
    with pytest.raises(EpochError, match="^authorization epoch is already initialized$"):
        state.initialize_epoch(2, key)


def test_state_schema_mismatch_detected(tmp_path):
    path = tmp_path / "state.sqlite"
    connection = sqlite3.connect(path)
    connection.executescript(
        "CREATE TABLE metadata (key TEXT PRIMARY KEY, value BLOB NOT NULL);"
    )
    connection.execute(
        "INSERT INTO metadata(key,value) VALUES('schema_version',?)", (b"2",)
    )
    connection.commit()
    connection.close()
    key = generate_private_key()
    with pytest.raises(StateIntegrityError, match="^security state schema mismatch$"):
        SecurityState(path, key.public_key(), 1)


def test_state_schema_is_created_with_version_one(tmp_path):
    state, _ = make_state(tmp_path / "state.sqlite")
    connection = sqlite3.connect(state.path)
    tables = {
        row[0]
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
    }
    assert {"metadata", "consumed_nonces"} <= tables
    version = connection.execute(
        "SELECT value FROM metadata WHERE key='schema_version'"
    ).fetchone()[0]
    connection.close()
    assert version == b"1"


def test_state_connect_prgmas(tmp_path):
    state, _ = make_state(tmp_path / "state.sqlite")
    connection = state._connect()
    journal = connection.execute("PRAGMA journal_mode").fetchone()[0]
    synchronous = connection.execute("PRAGMA synchronous").fetchone()[0]
    foreign_keys = connection.execute("PRAGMA foreign_keys").fetchone()[0]
    busy_timeout = connection.execute("PRAGMA busy_timeout").fetchone()[0]
    connection.close()
    assert journal == "wal"
    assert synchronous == 2
    assert foreign_keys == 1
    assert busy_timeout == 30000


def test_state_integrity_check_rejects_bad_header(tmp_path):
    state, key = make_state(tmp_path / "state.sqlite")
    state.initialize_epoch(1, key)
    state.path.write_bytes(b"garbage bytes, not an sqlite database file\n")
    with pytest.raises(StateIntegrityError, match="^security state file header is invalid$"):
        state.integrity_check()


def test_state_integrity_check_detects_schema_missing(tmp_path):
    state, key = make_state(tmp_path / "state.sqlite")
    state.initialize_epoch(1, key)
    connection = sqlite3.connect(state.path)
    connection.execute("UPDATE metadata SET value=? WHERE key='schema_version'", (b"9",))
    connection.commit()
    connection.close()
    with pytest.raises(StateIntegrityError, match="^security state schema missing or invalid$"):
        state.integrity_check()


def test_state_current_epoch_uninitialized(tmp_path):
    state, _ = make_state(tmp_path / "state.sqlite")
    with pytest.raises(EpochError, match="^authorization epoch is not initialized$"):
        state.current_epoch()


def test_state_decode_rejects_each_invalid_envelope(tmp_path):
    state, key = make_state(tmp_path / "state.sqlite")
    state.initialize_epoch(1, key)
    connection = sqlite3.connect(state.path)
    raw = connection.execute("SELECT value FROM metadata WHERE key='epoch_envelope'").fetchone()[0]
    connection.close()
    envelope = parse_canonical(raw)

    from mgk.canonical import canonicalize
    from mgk.crypto import EPOCH_DOMAIN, sign

    bad_doc = dict(envelope["document"])
    bad_doc["extra"] = 1
    tampered = canonicalize({"document": bad_doc, "signature": envelope["signature"]})
    with pytest.raises(EpochError, match="^invalid epoch document$"):
        state._decode_epoch(tampered)

    wrong_schema = dict(envelope["document"])
    wrong_schema["schema"] = "mgk-epoch/v9"
    tampered = canonicalize({"document": wrong_schema, "signature": envelope["signature"]})
    with pytest.raises(EpochError, match="^unsupported epoch schema$"):
        state._decode_epoch(tampered)

    wrong_key = dict(envelope["document"])
    wrong_key["key_id"] = "ed25519:" + "0" * 64
    tampered = canonicalize({"document": wrong_key, "signature": envelope["signature"]})
    with pytest.raises(EpochError, match="^epoch signer mismatch$"):
        state._decode_epoch(tampered)

    bad_epoch = dict(envelope["document"])
    bad_epoch["epoch"] = 0
    re_signed = canonicalize(
        {
            "document": bad_epoch,
            "signature": sign(key, EPOCH_DOMAIN, canonicalize(bad_epoch)),
        }
    )
    with pytest.raises(EpochError, match="^authorization epoch rollback or invalid epoch$"):
        state._decode_epoch(re_signed)

    wrong_doc = canonicalize({"document": {"epoch": 1}, "signature": envelope["signature"]})
    with pytest.raises(EpochError, match="^invalid epoch document$"):
        state._decode_epoch(wrong_doc)


def test_state_bump_epoch_exact_behavior(tmp_path):
    state, key = make_state(tmp_path / "state.sqlite")
    state.initialize_epoch(1, key)
    assert state.bump_epoch(key) == 2
    assert state.current_epoch() == 2
    assert state.expected_minimum_epoch == 2
    connection = sqlite3.connect(state.path)
    raw = connection.execute("SELECT value FROM metadata WHERE key='epoch_envelope'").fetchone()[0]
    connection.close()
    envelope = parse_canonical(raw)
    assert envelope["document"]["epoch"] == 2
    assert envelope["document"]["schema"] == "mgk-epoch/v1"


def test_state_consume_nonce_and_count(tmp_path):
    state, key = make_state(tmp_path / "state.sqlite")
    state.initialize_epoch(1, key)
    assert state.nonce_count() == 0
    state.consume_nonce("a" * 32, "cap-1", 100)
    assert state.nonce_count() == 1
    with pytest.raises(ReplayError, match="^nonce was already consumed$"):
        state.consume_nonce("a" * 32, "cap-1", 101)


def test_state_consume_nonce_rejects_invalid_request(tmp_path):
    state, key = make_state(tmp_path / "state.sqlite")
    state.initialize_epoch(1, key)
    for nonce, capability_id, consumed_at in (
        (None, "cap", 1),
        (123, "cap", 1),
        ("nonce", None, 1),
        ("nonce", "cap", "1"),
        ("nonce", "cap", None),
    ):
        with pytest.raises(ReplayError, match="^invalid nonce consumption request$"):
            state.consume_nonce(nonce, capability_id, consumed_at)


def test_state_epoch_floor_rejects_rollback(tmp_path):
    state, key = make_state(tmp_path / "state.sqlite")
    state.initialize_epoch(1, key)
    state.bump_epoch(key)
    snapshot = tmp_path / "snapshot.sqlite"
    with sqlite3.connect(state.path) as source, sqlite3.connect(snapshot) as target:
        source.backup(target)
    state.bump_epoch(key)
    restored = SecurityState(snapshot, key.public_key(), 3)
    with pytest.raises(EpochError, match="^authorization epoch rollback or invalid epoch$"):
        restored.current_epoch()