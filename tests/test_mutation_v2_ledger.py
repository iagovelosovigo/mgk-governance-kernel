from __future__ import annotations

import hashlib
import json
import os
import tempfile

import pytest

from mgk import AuditLedger, FailureLedger
from mgk.canonical import canonicalize, parse_canonical
from mgk.crypto import generate_private_key
from mgk.errors import AuditIntegrityError

GENESIS = "0" * 64


def make_ledger(tmp_path, private_key=True):
    audit_key = generate_private_key()
    ledger = AuditLedger(
        tmp_path / "audit.jsonl",
        tmp_path / "audit.checkpoint.json",
        audit_key.public_key(),
        audit_key if private_key else None,
    )
    return ledger, audit_key


def test_ledger_init_writes_genesis_checkpoint(tmp_path):
    ledger, audit_key = make_ledger(tmp_path)
    assert ledger.verify_integrity() == (0, GENESIS)
    checkpoint = parse_canonical(ledger.checkpoint_path.read_bytes().rstrip(b"\n"))
    assert set(checkpoint) == {"document", "signature"}
    document = checkpoint["document"]
    assert document == {
        "count": 0,
        "head_hash": GENESIS,
        "key_id": "ed25519:" + hashlib.sha256(audit_key.public_key().public_bytes_raw()).hexdigest(),
        "schema": "mgk-ledger-checkpoint/v1",
        "updated_at": 0,
    }


def test_ledger_verify_only_cannot_initialize(tmp_path):
    audit_key = generate_private_key()
    with pytest.raises(AuditIntegrityError, match="^cannot initialize a verify-only ledger$"):
        AuditLedger(
            tmp_path / "audit.jsonl",
            tmp_path / "audit.checkpoint.json",
            audit_key.public_key(),
            None,
        )


def test_ledger_partial_state_is_rejected(tmp_path):
    audit_key = generate_private_key()
    ledger_path = tmp_path / "audit.jsonl"
    ledger_path.touch()
    with pytest.raises(AuditIntegrityError, match="^partial audit ledger state$"):
        AuditLedger(
            ledger_path,
            tmp_path / "audit.checkpoint.json",
            audit_key.public_key(),
            audit_key,
        )


def test_ledger_append_returns_event_hash_and_exact_record(tmp_path):
    ledger, audit_key = make_ledger(tmp_path)
    event_hash = ledger.append("EXECUTION_AUTHORIZED", {"action": "resource.read"}, 100)
    assert len(event_hash) == 64
    assert int(event_hash, 16) >= 0
    line = parse_canonical(ledger.ledger_path.read_bytes().splitlines()[-1])
    assert set(line) == {"data", "event_hash", "event_type", "prev_hash", "seq", "timestamp"}
    assert line["event_type"] == "EXECUTION_AUTHORIZED"
    assert line["data"] == {"action": "resource.read"}
    assert line["prev_hash"] == GENESIS
    assert line["seq"] == 1
    assert line["timestamp"] == 100
    assert line["event_hash"] == event_hash
    expected = hashlib.sha256(
        canonicalize(
            {
                "data": {"action": "resource.read"},
                "event_type": "EXECUTION_AUTHORIZED",
                "prev_hash": GENESIS,
                "seq": 1,
                "timestamp": 100,
            }
        )
    ).hexdigest()
    assert event_hash == expected
    assert ledger.verify_integrity() == (1, event_hash)


def test_ledger_append_links_chain(tmp_path):
    ledger, _ = make_ledger(tmp_path)
    first = ledger.append("A", {"n": 1}, 10)
    second = ledger.append("B", {"n": 2}, 20)
    lines = [parse_canonical(l) for l in ledger.ledger_path.read_bytes().splitlines()]
    assert lines[0]["prev_hash"] == GENESIS
    assert lines[0]["seq"] == 1
    assert lines[1]["prev_hash"] == first
    assert lines[1]["seq"] == 2
    assert lines[1]["event_hash"] == second
    assert ledger.verify_integrity() == (2, second)


def test_ledger_append_updates_signed_checkpoint(tmp_path):
    ledger, _ = make_ledger(tmp_path)
    ledger.append("A", {}, 10)
    checkpoint = parse_canonical(ledger.checkpoint_path.read_bytes().rstrip(b"\n"))
    assert checkpoint["document"]["count"] == 1
    assert checkpoint["document"]["head_hash"] == ledger.verify_integrity()[1]
    assert checkpoint["document"]["updated_at"] == 10


def test_ledger_checkpoint_is_written_atomically(tmp_path):
    ledger, _ = make_ledger(tmp_path)
    ledger.append("A", {}, 10)
    leftovers = [p.name for p in tmp_path.glob("*.tmp")]
    assert leftovers == []
    assert ledger.checkpoint_path.name == "audit.checkpoint.json"


def test_ledger_append_rejects_invalid_request(tmp_path):
    ledger, _ = make_ledger(tmp_path)
    with pytest.raises(AuditIntegrityError, match="^invalid ledger append request$"):
        ledger.append("", {}, 1)
    with pytest.raises(AuditIntegrityError, match="^invalid ledger append request$"):
        ledger.append(123, {}, 1)
    with pytest.raises(AuditIntegrityError, match="^invalid ledger append request$"):
        ledger.append("A", None, 1)
    with pytest.raises(AuditIntegrityError, match="^invalid ledger append request$"):
        ledger.append("A", "not-a-dict", 1)
    with pytest.raises(AuditIntegrityError, match="^invalid ledger append timestamp$"):
        ledger.append("A", {}, -1)
    with pytest.raises(AuditIntegrityError, match="^invalid ledger append timestamp$"):
        ledger.append("A", {}, 1.5)
    with pytest.raises(AuditIntegrityError, match="^invalid ledger append timestamp$"):
        ledger.append("A", {}, "1")


def test_ledger_verify_only_rejects_append(tmp_path):
    audit_key = generate_private_key()
    writable = AuditLedger(
        tmp_path / "audit.jsonl",
        tmp_path / "audit.checkpoint.json",
        audit_key.public_key(),
        audit_key,
    )
    writable.append("A", {}, 1)
    verify_only = AuditLedger(
        tmp_path / "audit.jsonl",
        tmp_path / "audit.checkpoint.json",
        audit_key.public_key(),
        None,
    )
    assert verify_only.verify_integrity() == (1, writable.verify_integrity()[1])
    with pytest.raises(AuditIntegrityError, match="^ledger is verify-only$"):
        verify_only.append("A", {}, 2)


def test_ledger_scan_detects_each_corruption(tmp_path):
    ledger, audit_key = make_ledger(tmp_path)
    ledger.append("A", {"x": 1}, 10)
    line = ledger.ledger_path.read_bytes().splitlines()[-1]
    record = parse_canonical(line)

    def rebuild(body, event_hash=None):
        if event_hash is None:
            event_hash = hashlib.sha256(canonicalize(body)).hexdigest()
        rebuilt = dict(body)
        rebuilt["event_hash"] = event_hash
        return canonicalize(rebuilt) + b"\n"

    base = {
        "data": {"x": 1},
        "event_type": "A",
        "prev_hash": GENESIS,
        "seq": 1,
        "timestamp": 10,
    }

    missing_newline = line.rstrip(b"\n")
    ledger.ledger_path.write_bytes(missing_newline)
    with pytest.raises(AuditIntegrityError, match="^unterminated ledger record$"):
        ledger.verify_integrity()

    bad_schema = canonicalize({"data": {"x": 1}, "event_type": "A", "prev_hash": GENESIS, "seq": 1}) + b"\n"
    ledger.ledger_path.write_bytes(bad_schema)
    with pytest.raises(AuditIntegrityError, match="^invalid ledger record schema$"):
        ledger.verify_integrity()

    ledger.ledger_path.write_bytes(rebuild(base, event_hash="0" * 64))
    with pytest.raises(AuditIntegrityError, match="^ledger event hash mismatch$"):
        ledger.verify_integrity()

    bad_chain = dict(base)
    bad_chain["prev_hash"] = "1" * 64
    ledger.ledger_path.write_bytes(rebuild(bad_chain))
    with pytest.raises(AuditIntegrityError, match="^ledger chain discontinuity$"):
        ledger.verify_integrity()

    bad_seq = dict(base)
    bad_seq["seq"] = 2
    ledger.ledger_path.write_bytes(rebuild(bad_seq))
    with pytest.raises(AuditIntegrityError, match="^ledger chain discontinuity$"):
        ledger.verify_integrity()

    bad_time = dict(base)
    bad_time["timestamp"] = -1
    ledger.ledger_path.write_bytes(rebuild(bad_time))
    with pytest.raises(AuditIntegrityError, match="^invalid ledger timestamp$"):
        ledger.verify_integrity()

    bad_type = dict(base)
    bad_type["event_type"] = ""
    ledger.ledger_path.write_bytes(rebuild(bad_type))
    with pytest.raises(AuditIntegrityError, match="^invalid ledger event type$"):
        ledger.verify_integrity()

    ledger.ledger_path.write_bytes(b"{not-json}\n")
    with pytest.raises(AuditIntegrityError, match="^cannot scan ledger:"):
        ledger.verify_integrity()


def test_ledger_checkpoint_load_rejects_each_corruption(tmp_path):
    ledger, audit_key = make_ledger(tmp_path)
    ledger.append("A", {}, 10)
    checkpoint_bytes = ledger.checkpoint_path.read_bytes()
    envelope = parse_canonical(checkpoint_bytes.rstrip(b"\n"))

    def write(value):
        ledger.checkpoint_path.write_bytes(canonicalize(value) + b"\n")

    write({"document": envelope["document"]})
    with pytest.raises(AuditIntegrityError, match="^invalid checkpoint envelope$"):
        ledger.verify_integrity()

    bad_doc = dict(envelope["document"])
    bad_doc.pop("updated_at")
    write({"document": bad_doc, "signature": envelope["signature"]})
    with pytest.raises(AuditIntegrityError, match="^invalid checkpoint schema$"):
        ledger.verify_integrity()

    bad_schema = dict(envelope["document"])
    bad_schema["schema"] = "mgk-ledger-checkpoint/v9"
    write({"document": bad_schema, "signature": envelope["signature"]})
    with pytest.raises(AuditIntegrityError, match="^unsupported checkpoint schema$"):
        ledger.verify_integrity()

    bad_key = dict(envelope["document"])
    bad_key["key_id"] = "ed25519:" + "0" * 64
    write({"document": bad_key, "signature": envelope["signature"]})
    with pytest.raises(AuditIntegrityError, match="^checkpoint signer mismatch$"):
        ledger.verify_integrity()

    bad_count = dict(envelope["document"])
    bad_count["count"] = -1
    write({"document": bad_count, "signature": envelope["signature"]})
    with pytest.raises(AuditIntegrityError, match="^invalid checkpoint count$"):
        ledger.verify_integrity()

    bad_time = dict(envelope["document"])
    bad_time["updated_at"] = -1
    write({"document": bad_time, "signature": envelope["signature"]})
    with pytest.raises(AuditIntegrityError, match="^invalid checkpoint time$"):
        ledger.verify_integrity()

    bad_head = dict(envelope["document"])
    bad_head["head_hash"] = "x" * 63
    write({"document": bad_head, "signature": envelope["signature"]})
    with pytest.raises(AuditIntegrityError, match="^invalid checkpoint head$"):
        ledger.verify_integrity()

    ledger.checkpoint_path.write_bytes(canonicalize(envelope).rstrip(b"\n"))
    with pytest.raises(AuditIntegrityError, match="^checkpoint newline missing$"):
        ledger.verify_integrity()

    ledger.checkpoint_path.write_bytes(b"{not-json}\n")
    with pytest.raises(AuditIntegrityError, match="^cannot parse ledger checkpoint:"):
        ledger.verify_integrity()


def test_ledger_detects_checkpoint_ledger_mismatch(tmp_path):
    from mgk.crypto import AUDIT_DOMAIN, sign

    ledger, audit_key = make_ledger(tmp_path)
    ledger.append("A", {}, 10)
    checkpoint_bytes = ledger.checkpoint_path.read_bytes()
    envelope = parse_canonical(checkpoint_bytes.rstrip(b"\n"))
    wrong = dict(envelope["document"])
    wrong["count"] = 0
    tampered = canonicalize(
        {
            "document": wrong,
            "signature": sign(audit_key, AUDIT_DOMAIN, canonicalize(wrong)),
        }
    )
    ledger.checkpoint_path.write_bytes(tampered + b"\n")
    with pytest.raises(AuditIntegrityError, match="^ledger does not match signed checkpoint$"):
        ledger.verify_integrity()


def test_ledger_detects_signature_tampering(tmp_path):
    ledger, _ = make_ledger(tmp_path)
    ledger.append("A", {}, 10)
    checkpoint_bytes = ledger.checkpoint_path.read_bytes()
    envelope = parse_canonical(checkpoint_bytes.rstrip(b"\n"))
    bad_signature = dict(envelope)
    bad_signature["signature"] = "0" * 64
    ledger.checkpoint_path.write_bytes(canonicalize(bad_signature) + b"\n")
    with pytest.raises(AuditIntegrityError, match="^checkpoint signature failed:"):
        ledger.verify_integrity()


def test_ledger_checkpoint_uses_expected_tempfile_parameters(tmp_path, monkeypatch):
    ledger, _ = make_ledger(tmp_path)
    observed = {}
    original = tempfile.mkstemp

    def tracked(*args, **kwargs):
        observed["prefix"] = kwargs.get("prefix")
        observed["suffix"] = kwargs.get("suffix")
        observed["dir"] = kwargs.get("dir")
        return original(*args, **kwargs)

    monkeypatch.setattr(tempfile, "mkstemp", tracked)
    ledger.append("A", {}, 10)
    assert observed["prefix"] == "audit.checkpoint.json."
    assert observed["suffix"] == ".tmp"
    assert observed["dir"] == tmp_path


def test_failure_ledger_record_uses_failure_event(tmp_path):
    audit_key = generate_private_key()
    failures = FailureLedger(
        tmp_path / "failures.jsonl",
        tmp_path / "failures.checkpoint.json",
        audit_key.public_key(),
        audit_key,
    )
    failures.record({"code": "REPLAY_ERROR"}, 100)
    line = parse_canonical(failures.ledger_path.read_bytes().splitlines()[-1])
    assert line["event_type"] == "FAILURE"
    assert line["data"] == {"code": "REPLAY_ERROR"}
    assert failures.verify_integrity() == (1, line["event_hash"])