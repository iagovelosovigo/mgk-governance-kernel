"""Security adequacy discriminating tests (v3).

These tests express the security invariants that survived the full-population
mutation run. Each test is written to FAIL when the corresponding mutant family
is applied, so the tests permanently kill the v0.2.0 survivors:

  POLICY_PRESERVATION   - a supplied restrictive policy is never silently broadened
  EPOCH_MONOTONICITY    - a stale writer must never reduce authorization_epoch
  ROLLBACK_CONFINEMENT  - rollback stays anchored to the authorized dir_fd / root
  RESOURCE_IDENTITY     - same length but different digest is NOT the same resource
  RESOURCE_PERMISSIONS  - protected resources stay 0600 under umask 0
  plus exact-boundary checks that the full-population survivors weakened.
"""

from __future__ import annotations

import hashlib
import os
import stat as stat_mod

import pytest

from mgk import (
    ActionRequest,
    ResourceGuard,
    SAXPContext,
    SAXPEvaluator,
    SecurityState,
)
from mgk.canonical import MAX_CANONICAL_BYTES, MAX_DEPTH, MAX_ITEMS, canonicalize, digest
from mgk.crypto import b64u_encode
from mgk.errors import CanonicalizationError, EpochError, ResourceError
from mgk.ledger import AuditLedger
from mgk.resource import MAX_RESOURCE_BYTES

from .helpers import read_request


# ---------------------------------------------------------------------------
# resource: exact boundary + rollback + identity + permissions
# ---------------------------------------------------------------------------


def make_guard(tmp_path):
    root = tmp_path / "resources"
    (root / "workspace").mkdir(parents=True)
    return ResourceGuard(root), root


def sha(data):
    return hashlib.sha256(data).hexdigest()


class _FailingWrite:
    """Injects controlled short-write behavior into os.write for the test scope."""

    def __init__(self, fail_after=None, partial=None, zero_once=False):
        self.calls = 0
        self.fail_after = fail_after
        self.partial = partial
        self.zero_once = zero_once
        self._real = os.write

    def __enter__(self):
        os.write = self._write
        return self

    def _write(self, fd, buf):
        self.calls += 1
        if self.fail_after is not None and self.calls == self.fail_after:
            raise OSError("injected write failure")
        if self.zero_once and self.calls == 1:
            return 0
        if self.partial is not None and self.calls == 1:
            n = self.partial
            return self._real(fd, bytes(buf[:n]))
        return self._real(fd, buf)

    def __exit__(self, *exc):
        os.write = self._real
        return False


def test_resource_create_exact_max_bytes_accepted(tmp_path):
    guard, root = make_guard(tmp_path)
    data = b"x" * MAX_RESOURCE_BYTES
    binding = guard.bind_absent("workspace/big.txt", sha(data), len(data))
    returned = guard.create_bound(binding, data)
    assert returned == sha(data)
    assert (root / "workspace" / "big.txt").stat().st_size == MAX_RESOURCE_BYTES


def test_resource_create_over_limit_rejected(tmp_path):
    guard, root = make_guard(tmp_path)
    data = b"x" * (MAX_RESOURCE_BYTES + 1)
    with pytest.raises(ResourceError, match="^invalid post-state size$"):
        guard.bind_absent("workspace/big.txt", sha(data), len(data))


@pytest.mark.parametrize(
    "op",
    ["create", "write"],
)
def test_resource_rollback_removes_created_file_and_stays_confined(tmp_path, op):
    guard, root = make_guard(tmp_path)
    cwd_dir = tmp_path / "cwd"
    (cwd_dir / "workspace").mkdir(parents=True)
    (cwd_dir / "workspace" / "t.txt").write_bytes(b"DECOY")
    cwd_before = os.getcwd()
    os.chdir(cwd_dir)
    try:
        data = b"payload"
        binding = (
            guard.bind_absent("workspace/t.txt", sha(data), len(data))
            if op == "create"
            else guard.bind_write("workspace/t.txt", data)
        )
        with _FailingWrite(fail_after=1):
            with pytest.raises(OSError, match="injected write failure"):
                if op == "create":
                    guard.create_bound(binding, data)
                else:
                    guard.write_bound(binding, data)
    finally:
        os.chdir(cwd_before)
    assert not (root / "workspace" / "t.txt").exists(), "rollback must remove the created resource"
    assert (cwd_dir / "workspace" / "t.txt").read_bytes() == b"DECOY", "rollback must not touch CWD files"


def test_resource_write_rejects_tampered_present_file(tmp_path):
    guard, root = make_guard(tmp_path)
    (root / "workspace" / "t.txt").write_bytes(b"original content")
    binding = guard.bind_write("workspace/t.txt", b"new content")
    (root / "workspace" / "t.txt").write_bytes(b"ORIGINAL CONTENT")
    with pytest.raises(ResourceError, match="^write target changed after authorization$"):
        guard.write_bound(binding, b"new content")


def test_resource_append_rejects_tampered_present_file(tmp_path):
    guard, root = make_guard(tmp_path)
    (root / "workspace" / "t.txt").write_bytes(b"base")
    binding = guard.bind_append("workspace/t.txt", b"tail")
    (root / "workspace" / "t.txt").write_bytes(b"BASE")
    with pytest.raises(ResourceError, match="^append target changed after authorization$"):
        guard.append_bound(binding, b"tail")


def test_resource_remove_created_refuses_same_size_tampered(tmp_path):
    guard, root = make_guard(tmp_path)
    data = b"AAAA"
    binding = guard.bind_absent("workspace/r.txt", sha(data), len(data))
    guard.create_bound(binding, data)
    (root / "workspace" / "r.txt").write_bytes(b"BBBB")
    assert guard.remove_created(binding, sha(data)) is False
    assert (root / "workspace" / "r.txt").exists()


def test_resource_guard_rejects_symlink_file_target(tmp_path):
    guard, root = make_guard(tmp_path)
    outside = tmp_path / "outside.txt"
    outside.write_bytes(b"secret")
    (root / "workspace" / "link.txt").symlink_to(outside)
    with pytest.raises((ResourceError, OSError)):
        guard.bind_write("workspace/link.txt", b"data")


def test_resource_guard_rejects_symlink_parent(tmp_path):
    guard, root = make_guard(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "file.txt").write_bytes(b"secret")
    (root / "workspace" / "linkdir").symlink_to(outside, target_is_directory=True)
    with pytest.raises((ResourceError, OSError)):
        guard.bind_present("workspace/linkdir/file.txt")


def test_resource_create_mode_0600_under_umask_zero(tmp_path):
    guard, root = make_guard(tmp_path)
    data = b"x"
    binding = guard.bind_absent("workspace/p.txt", sha(data), len(data))
    old_umask = os.umask(0)
    try:
        guard.create_bound(binding, data)
    finally:
        os.umask(old_umask)
    mode = stat_mod.S_IMODE((root / "workspace" / "p.txt").stat().st_mode)
    assert mode == 0o600


def test_resource_short_write_completes_single_byte(tmp_path):
    guard, root = make_guard(tmp_path)
    data = b"a"
    binding = guard.bind_absent("workspace/s.txt", sha(data), len(data))
    assert guard.create_bound(binding, data) == sha(data)
    assert (root / "workspace" / "s.txt").read_bytes() == b"a"


def test_resource_partial_write_loop_completes(tmp_path):
    guard, root = make_guard(tmp_path)
    data = b"abcdefgh" * 4
    binding = guard.bind_absent("workspace/p.txt", sha(data), len(data))
    with _FailingWrite(partial=8):
        guard.create_bound(binding, data)
    assert (root / "workspace" / "p.txt").read_bytes() == data


@pytest.mark.parametrize(
    "op",
    ["create", "write", "append"],
)
def test_resource_zero_write_is_short_write_error(tmp_path, op):
    guard, root = make_guard(tmp_path)
    data = b"abcdefgh" * 4
    if op == "create":
        binding = guard.bind_absent("workspace/z.txt", sha(data), len(data))
        with _FailingWrite(zero_once=True):
            with pytest.raises(ResourceError, match="short write"):
                guard.create_bound(binding, data)
    elif op == "write":
        binding = guard.bind_write("workspace/z.txt", data)
        with _FailingWrite(zero_once=True):
            with pytest.raises(ResourceError, match="short write"):
                guard.write_bound(binding, data)
    else:
        (root / "workspace" / "z.txt").write_bytes(b"")
        binding = guard.bind_append("workspace/z.txt", data)
        with _FailingWrite(zero_once=True):
            with pytest.raises(ResourceError, match="short write"):
                guard.append_bound(binding, data)


@pytest.mark.parametrize(
    "op",
    ["write", "append"],
)
def test_resource_partial_write_completes_and_persists(tmp_path, op):
    guard, root = make_guard(tmp_path)
    data = b"abcdefgh" * 4
    if op == "write":
        binding = guard.bind_write("workspace/p.txt", data)
        with _FailingWrite(partial=8):
            returned = guard.write_bound(binding, data)
    else:
        (root / "workspace" / "p.txt").write_bytes(b"")
        binding = guard.bind_append("workspace/p.txt", data)
        with _FailingWrite(partial=8):
            returned = guard.append_bound(binding, data)
    assert returned == sha(data)
    assert (root / "workspace" / "p.txt").read_bytes() == data


def test_resource_write_toctou_symlink_swap_rejected(tmp_path):
    guard, root = make_guard(tmp_path)
    outside = tmp_path / "outside.txt"
    pre = b"original content"
    outside.write_bytes(pre)
    target = root / "workspace" / "t.txt"
    target.write_bytes(pre)
    binding = guard.bind_write("workspace/t.txt", b"new content")
    target.unlink()
    target.symlink_to(outside)
    with pytest.raises((ResourceError, OSError)):
        guard.write_bound(binding, b"new content")
    assert outside.read_bytes() == pre, "outside file must never be modified through a symlink"


def test_resource_append_toctou_symlink_swap_rejected(tmp_path):
    guard, root = make_guard(tmp_path)
    outside = tmp_path / "outside.txt"
    pre = b"base"
    outside.write_bytes(pre)
    target = root / "workspace" / "t.txt"
    target.write_bytes(pre)
    binding = guard.bind_append("workspace/t.txt", b"tail")
    target.unlink()
    target.symlink_to(outside)
    with pytest.raises((ResourceError, OSError)):
        guard.append_bound(binding, b"tail")
    assert outside.read_bytes() == pre, "outside file must never be modified through a symlink"


def test_resource_remove_created_rejects_symlink_swap(tmp_path):
    guard, root = make_guard(tmp_path)
    outside = tmp_path / "outside.txt"
    data = b"secret"
    outside.write_bytes(data)
    target = root / "workspace" / "r.txt"
    binding = guard.bind_absent("workspace/r.txt", sha(data), len(data))
    guard.create_bound(binding, data)
    assert (root / "workspace" / "r.txt").exists()
    target.unlink()
    target.symlink_to(outside)
    assert guard.remove_created(binding, sha(data)) is False
    assert target.is_symlink(), "rollback must not follow a symlink"
    assert outside.read_bytes() == data, "outside file must never be unlinked through a symlink"


def test_resource_create_rejects_symlink_target_after_binding(tmp_path):
    guard, root = make_guard(tmp_path)
    outside = tmp_path / "outside.txt"
    outside.write_bytes(b"secret")
    target = root / "workspace" / "c.txt"
    binding = guard.bind_absent("workspace/c.txt", sha(b"data"), 4)
    target.symlink_to(outside)
    with pytest.raises((ResourceError, OSError)):
        guard.create_bound(binding, b"data")
    assert outside.read_bytes() == b"secret"


# ---------------------------------------------------------------------------
# executor: consume_nonce default is True (mutmut_12 removed the explicit kwarg)
# ---------------------------------------------------------------------------


def test_authority_rejects_oversized_create_payload_at_issue(kernel_factory):
    kernel = kernel_factory()
    data = b"x" * (MAX_RESOURCE_BYTES + 1)
    request = ActionRequest(
        request_id="big-1",
        principal="planner",
        audience="executor",
        action="resource.create",
        resource="workspace/big.bin",
        parameters={"content_b64": b64u_encode(data)},
    )
    with pytest.raises(CanonicalizationError, match="size limit"):
        kernel.authority.issue(request)
    assert not (kernel.root / "resources" / "workspace" / "big.bin").exists()


def test_executor_rejects_replayed_envelope(kernel_factory):
    kernel = kernel_factory()
    request = read_request()
    issued = kernel.authority.issue(request)
    first = kernel.executor.execute(issued.envelope, request)
    assert first.success is True
    second = kernel.executor.execute(issued.envelope, request)
    assert second.success is False
    assert second.execution_authority == 0


def test_executor_rolls_back_sandbox_create_record_on_ledger_failure(kernel_factory):
    from mgk.authority import AuthorityPolicy

    kernel = kernel_factory()
    kernel.authority.policy = AuthorityPolicy(
        allowed_actions=frozenset(
            {"resource.read", "resource.create", "sandbox.create_record"}
        ),
    )
    request = ActionRequest(
        request_id="sr-1",
        principal="planner",
        audience="executor",
        action="sandbox.create_record",
        resource="workspace/rec1",
        parameters={"content_b64": b64u_encode(b'{"a": 1}')},
    )
    issued = kernel.authority.issue(request)
    real_append = kernel.audit.append
    calls = []

    def flaky_append(*args, **kwargs):
        calls.append(args)
        if len(calls) == 2:
            raise OSError("injected audit failure")
        return real_append(*args, **kwargs)

    kernel.audit.append = flaky_append
    result = kernel.executor.execute(issued.envelope, request)
    assert result.success is False
    assert not (kernel.root / "resources" / "workspace" / "rec1").exists()


def test_resource_write_rejects_dangling_symlink_target(tmp_path):
    guard, root = make_guard(tmp_path)
    data = b"new content"
    binding = guard.bind_write("workspace/d.txt", data)
    (root / "workspace" / "d.txt").symlink_to(root / "missing-target.txt")
    with pytest.raises(ResourceError):
        guard.write_bound(binding, data)


def test_resource_write_absent_rejects_appeared_target_even_when_stat_is_blind(
    tmp_path, monkeypatch
):
    guard, root = make_guard(tmp_path)
    data = b"new content"
    binding = guard.bind_write("workspace/r.txt", data)
    (root / "workspace" / "r.txt").write_bytes(b"attacker")
    real_stat = os.stat

    def blind_stat(name, dir_fd=None, follow_symlinks=True):
        raise FileNotFoundError(2, "blind stat")

    monkeypatch.setattr(os, "stat", blind_stat)
    with pytest.raises(ResourceError):
        guard.write_bound(binding, data)


def test_resource_create_readonly_parent_raises_oserror(tmp_path):
    guard, root = make_guard(tmp_path)
    data = b"data"
    binding = guard.bind_absent("workspace/ro.txt", sha(data), len(data))
    os.chmod(root / "workspace", 0o500)
    try:
        with pytest.raises(OSError):
            guard.create_bound(binding, data)
    finally:
        os.chmod(root / "workspace", 0o700)


# ---------------------------------------------------------------------------
# saxp: exact evaluation boundaries + policy defaults
# ---------------------------------------------------------------------------


def grant_context(**over):
    base = dict(
        coherence_delta=0,
        systemic_pressure=5,
        threshold_k=10,
        sentidino=9000,
        information_complete=True,
        critical_uncertainty=False,
        control_risk=False,
        ethical_constraints_satisfied=True,
    )
    base.update(over)
    return SAXPContext(**base)


def test_saxp_coherence_delta_zero_grants_ten_xeito():
    evaluator = SAXPEvaluator()
    decision = evaluator.evaluate(read_request(), grant_context(coherence_delta=0))
    assert decision.result == "TEN_XEITO"


def test_saxp_systemic_pressure_at_threshold_grants():
    evaluator = SAXPEvaluator()
    decision = evaluator.evaluate(read_request(), grant_context(systemic_pressure=10, threshold_k=10))
    assert decision.result == "TEN_XEITO"


def test_saxp_sentidino_at_minimum_grants():
    evaluator = SAXPEvaluator(minimum_sentidino=9000)
    decision = evaluator.evaluate(read_request(), grant_context(sentidino=9000))
    assert decision.result == "TEN_XEITO"


def test_saxp_minimum_sentidino_zero_accepted():
    assert SAXPEvaluator(minimum_sentidino=0).minimum_sentidino == 0


# ---------------------------------------------------------------------------
# canonical: list normalization, depth/budget boundaries, size boundary
# ---------------------------------------------------------------------------


def test_canonicalize_nested_list_nfc_normalized():
    assert digest(["\u0065\u0301"]) == digest(["\u00e9"])


def test_canonicalize_max_depth_exact_accepted():
    value = 1
    for _ in range(MAX_DEPTH):
        value = [value]
    canonicalize(value)
    over = 1
    for _ in range(MAX_DEPTH + 1):
        over = [over]
    with pytest.raises(CanonicalizationError, match="nesting limit"):
        canonicalize(over)


def test_canonicalize_max_items_exact_accepted():
    canonicalize(list(range(MAX_ITEMS - 1)))
    with pytest.raises(CanonicalizationError, match="item limit"):
        canonicalize(list(range(MAX_ITEMS)))


def test_canonicalize_large_list_budget_not_double_charged():
    canonicalize(list(range(3000)))


def test_canonicalize_max_bytes_exact_boundary():
    body = "e" * (MAX_CANONICAL_BYTES - 2)
    assert len(canonicalize(body)) == MAX_CANONICAL_BYTES
    with pytest.raises(CanonicalizationError, match="size limit"):
        canonicalize(body + "ee")


# ---------------------------------------------------------------------------
# state: parent dirs, autocommit isolation, stale-writer epoch protection
# ---------------------------------------------------------------------------


@pytest.fixture
def epoch_key():
    from mgk.crypto import generate_private_key

    return generate_private_key()


def test_security_state_creates_nested_parent_dirs(tmp_path, epoch_key):
    db = tmp_path / "a" / "b" / "c" / "state.sqlite"
    state = SecurityState(db, epoch_key.public_key())
    assert db.exists()
    state.initialize_epoch(1, epoch_key)
    assert state.current_epoch() == 1


def test_security_state_connection_is_autocommit(tmp_path, epoch_key):
    state = SecurityState(tmp_path / "state.sqlite", epoch_key.public_key())
    with state._connect() as connection:
        assert connection.isolation_level is None


def test_security_state_busy_timeout_is_pragma_30000(tmp_path, epoch_key):
    state = SecurityState(tmp_path / "state.sqlite", epoch_key.public_key())
    with state._connect() as connection:
        (busy,) = connection.execute("PRAGMA busy_timeout").fetchone()
        assert busy == 30000


def test_bump_epoch_rejects_stale_writer(tmp_path, epoch_key):
    db = tmp_path / "state.sqlite"
    writer = SecurityState(db, epoch_key.public_key())
    writer.initialize_epoch(1, epoch_key)
    writer.bump_epoch(epoch_key)
    writer.bump_epoch(epoch_key)
    assert writer.current_epoch() == 3

    class StaleWriter(SecurityState):
        def __init__(self, path, public_key, stale):
            super().__init__(path, public_key)
            self._stale = stale

        def current_epoch(self):
            return self._stale

    stale = StaleWriter(db, epoch_key.public_key(), 1)
    with pytest.raises(EpochError, match="concurrently"):
        stale.bump_epoch(epoch_key)
    fresh = SecurityState(db, epoch_key.public_key())
    assert fresh.current_epoch() == 3


# ---------------------------------------------------------------------------
# ledger: nested dirs, 0600 mode, double-init rejection, timestamp 0
# ---------------------------------------------------------------------------


@pytest.fixture
def ledger_key():
    from mgk.crypto import generate_private_key

    return generate_private_key()


def test_audit_ledger_creates_nested_dirs(tmp_path, ledger_key):
    ledger_path = tmp_path / "a" / "b" / "audit.jsonl"
    checkpoint_path = tmp_path / "c" / "d" / "checkpoint.json"
    ledger = AuditLedger(ledger_path, checkpoint_path, ledger_key.public_key(), ledger_key)
    assert ledger_path.exists() and checkpoint_path.exists()
    ledger.append("TEST", {"ok": True}, 1)
    count, head = ledger.verify_integrity()
    assert count == 1


def test_audit_ledger_file_mode_0600(tmp_path, ledger_key):
    ledger_path = tmp_path / "audit.jsonl"
    checkpoint_path = tmp_path / "checkpoint.json"
    AuditLedger(ledger_path, checkpoint_path, ledger_key.public_key(), ledger_key)
    assert stat_mod.S_IMODE(ledger_path.stat().st_mode) == 0o600


def test_audit_ledger_append_timestamp_zero(tmp_path, ledger_key):
    ledger = AuditLedger(
        tmp_path / "audit.jsonl", tmp_path / "checkpoint.json", ledger_key.public_key(), ledger_key
    )
    assert ledger.append("TEST", {"ts": 0}, 0)
    assert ledger.verify_integrity()[0] == 1


# ---------------------------------------------------------------------------
# authority: 8 MiB create is NOT issuable through issue() because request.digest()
# canonicalizes parameters (content_b64) and is capped by MAX_CANONICAL_BYTES.
# The MAX_RESOURCE_BYTES boundary in _bind_resource is therefore unreachable via
# the public flow; the resource-level exact-boundary test above is the guard.
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# v0.3.0 additions: exact-MAX authority binding and CWD-independent absent-write
# ---------------------------------------------------------------------------


def test_authority_bind_accepts_exactly_max_resource_bytes(kernel_factory):
    # Pins `if len(data) > MAX_RESOURCE_BYTES` (mutmut_29): the exact boundary
    # must still be bindable at the authority layer. A mutant changing the
    # comparison to `>=` rejects it with SchemaError.
    kernel = kernel_factory()
    data = b"x" * MAX_RESOURCE_BYTES
    request = ActionRequest(
        request_id="max-1",
        principal="planner",
        audience="executor",
        action="resource.create",
        resource="workspace/max.bin",
        parameters={"content_b64": b64u_encode(data)},
    )
    binding = kernel.authority._bind_resource_dispatch(request)
    assert binding["post_size"] == MAX_RESOURCE_BYTES


def test_resource_write_bound_absent_ignores_cwd_decoy(tmp_path):
    # Pins `os.stat(name, dir_fd=parent, follow_symlinks=False)` in write_bound
    # (mutmut_69): the absent-target revalidation must resolve relative to the
    # guarded parent directory, never the process CWD. A mutant using
    # `dir_fd=None` is distracted by a same-named file in the CWD and raises a
    # spurious "appeared after authorization" rejection.
    guard, root = make_guard(tmp_path)
    decoy_dir = tmp_path / "decoy"
    decoy_dir.mkdir()
    (decoy_dir / "t.txt").write_bytes(b"decoy")
    cwd_before = os.getcwd()
    os.chdir(decoy_dir)
    try:
        data = b"payload"
        binding = guard.bind_write("workspace/t.txt", data)
        returned = guard.write_bound(binding, data)
    finally:
        os.chdir(cwd_before)
    assert returned == sha(data)
    assert (root / "workspace" / "t.txt").read_bytes() == data
    assert (decoy_dir / "t.txt").read_bytes() == b"decoy"