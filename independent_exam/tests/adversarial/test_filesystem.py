from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from api_contract import request
from tests.helpers import Counter, assert_denied


pytestmark = [pytest.mark.adversarial, pytest.mark.protected]


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_path_traversal_is_non_ten_xeito(harness):
    req = request(action="fs.write", resource="../../authority/private-key")
    decision = harness.evaluate(
        harness.propose(req), {"permitted": True, "evidence_complete": True}
    )
    assert decision.get("outcome") == "NON_TEN_XEITO"


def test_symlink_resource_is_denied(harness, tmp_path):
    outside = tmp_path / "outside"
    outside.write_text("protected", encoding="utf-8")
    link = tmp_path / "resource"
    link.symlink_to(outside)
    req = request(
        action="fs.write", resource=str(link), resource_digest=_digest(outside)
    )
    try:
        cap = harness.issue(req, nonce="n-symlink-1")
    except (ValueError, RuntimeError):
        assert outside.read_text(encoding="utf-8") == "protected"
        return
    counter = Counter()
    assert_denied(harness.execute(cap, req, counter.operation), counter)
    assert outside.read_text(encoding="utf-8") == "protected"


def test_toctou_replacement_between_verify_and_commit_is_denied(harness, tmp_path):
    victim = tmp_path / "victim"
    replacement = tmp_path / "replacement"
    victim.write_text("authorized", encoding="utf-8")
    replacement.write_text("forbidden", encoding="utf-8")
    req = request(
        action="fs.write", resource=str(victim), resource_digest=_digest(victim)
    )
    cap = harness.issue(req, nonce="n-toctou-1")

    def replace():
        victim.unlink()
        victim.symlink_to(replacement)

    counter = Counter()
    assert_denied(
        harness.execute(cap, req, counter.operation, before_commit=replace), counter
    )
    assert replacement.read_text(encoding="utf-8") == "forbidden"
