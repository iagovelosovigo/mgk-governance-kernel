from __future__ import annotations

import hashlib

import pytest

from mgk import ResourceGuard
from mgk.crypto import b64u_encode
from mgk.errors import ResourceError


def make_guard(tmp_path):
    root = tmp_path / "resources"
    (root / "workspace").mkdir(parents=True)
    (root / "workspace" / "file.txt").write_bytes(b"hello\n")
    return ResourceGuard(root), root


def test_resource_guard_rejects_non_directory_root(tmp_path):
    with pytest.raises(ResourceError, match="^resource root must be a real directory$"):
        ResourceGuard(tmp_path / "missing")
    file_root = tmp_path / "afile"
    file_root.write_bytes(b"x")
    with pytest.raises(ResourceError, match="^resource root must be a real directory$"):
        ResourceGuard(file_root)


def test_bind_absent_rejects_bad_binding(tmp_path):
    guard, root = make_guard(tmp_path)
    with pytest.raises(ResourceError, match="^invalid post-state binding$"):
        guard.bind_absent("workspace/new.txt", "not-hex", 3)
    with pytest.raises(ResourceError, match="^invalid post-state binding$"):
        guard.bind_absent("workspace/new.txt", hashlib.sha256(b"abc").hexdigest(), 3.5)
    with pytest.raises(ResourceError, match="^invalid post-state size$"):
        guard.bind_absent("workspace/new.txt", hashlib.sha256(b"abc").hexdigest(), -1)
    with pytest.raises(ResourceError, match="^create target already exists$"):
        guard.bind_absent("workspace/file.txt", hashlib.sha256(b"x").hexdigest(), 1)


def test_bind_absent_exact_dict(tmp_path):
    guard, root = make_guard(tmp_path)
    sha = hashlib.sha256(b"abc").hexdigest()
    binding = guard.bind_absent("workspace/new.txt", sha, 3)
    assert binding == {
        "path": "workspace/new.txt",
        "post_sha256": sha,
        "post_size": 3,
        "state": "absent",
    }


def test_create_bound_rejects_bad_binding(tmp_path):
    guard, root = make_guard(tmp_path)
    sha = hashlib.sha256(b"abc").hexdigest()
    valid = guard.bind_absent("workspace/new.txt", sha, 3)
    with pytest.raises(ResourceError, match="^invalid absent-resource binding$"):
        guard.create_bound({"path": "workspace/new.txt", "state": "absent"}, b"abc")
    with pytest.raises(ResourceError, match="^invalid create request$"):
        bad = dict(valid)
        bad["state"] = "present"
        guard.create_bound(bad, b"abc")
    with pytest.raises(ResourceError, match="^invalid create request$"):
        guard.create_bound(valid, "not-bytes")
    with pytest.raises(ResourceError, match="^create payload does not match capability binding$"):
        guard.create_bound(valid, b"abd")
    with pytest.raises(ResourceError, match="^create payload does not match capability binding$"):
        guard.create_bound(valid, b"abcd")


def test_create_bound_and_remove_created_exact(tmp_path):
    guard, root = make_guard(tmp_path)
    data = b"new content\n"
    sha = hashlib.sha256(data).hexdigest()
    binding = guard.bind_absent("workspace/created.txt", sha, len(data))
    returned = guard.create_bound(binding, data)
    assert returned == sha
    created = root / "workspace" / "created.txt"
    assert created.read_bytes() == data
    assert guard.remove_created(binding, sha) is True
    assert not created.exists()
    assert guard.remove_created(binding, sha) is False


def test_remove_created_rejects_digest_mismatch(tmp_path):
    guard, root = make_guard(tmp_path)
    data = b"data\n"
    sha = hashlib.sha256(data).hexdigest()
    binding = guard.bind_absent("workspace/created.txt", sha, len(data))
    guard.create_bound(binding, data)
    assert guard.remove_created(binding, hashlib.sha256(b"other").hexdigest()) is False
    assert (root / "workspace" / "created.txt").exists()


def test_bind_absent_rejects_oversize(tmp_path):
    from mgk.resource import MAX_RESOURCE_BYTES

    guard, root = make_guard(tmp_path)
    data = b"x" * (MAX_RESOURCE_BYTES + 1)
    sha = hashlib.sha256(data).hexdigest()
    with pytest.raises(ResourceError, match="^invalid post-state size$"):
        guard.bind_absent("workspace/big.txt", sha, len(data))


def test_read_bound_rejects_binding_and_hash_change(tmp_path):
    guard, root = make_guard(tmp_path)
    binding = guard.bind_present("workspace/file.txt")
    assert binding["state"] == "present"
    assert guard.read_bound(binding) == b"hello\n"
    with pytest.raises(ResourceError, match="^invalid present-resource binding$"):
        guard.read_bound({"path": "workspace/file.txt", "state": "present"})
    bad_sha = dict(binding)
    bad_sha["sha256"] = "0" * 64
    with pytest.raises(ResourceError, match="^resource changed after authorization$"):
        guard.read_bound(bad_sha)
    bad_size = dict(binding)
    bad_size["size"] = binding["size"] + 1
    with pytest.raises(ResourceError, match="^resource changed after authorization$"):
        guard.read_bound(bad_size)


def test_open_file_rejects_missing_and_directory(tmp_path):
    guard, root = make_guard(tmp_path)
    with pytest.raises(ResourceError, match="^cannot open bound resource: No such file or directory$"):
        guard.bind_present("workspace/missing.txt")
    (root / "workspace" / "subdir").mkdir()
    with pytest.raises(ResourceError, match="^bound resource is not a regular file$"):
        guard.bind_present("workspace/subdir")


def test_create_target_race_fails_closed(tmp_path):
    guard, root = make_guard(tmp_path)
    data = b"abc"
    sha = hashlib.sha256(data).hexdigest()
    binding = guard.bind_absent("workspace/race.txt", sha, 3)
    (root / "workspace" / "race.txt").write_bytes(b"racer")
    with pytest.raises(ResourceError, match="^create target appeared after authorization$"):
        guard.create_bound(binding, data)
    assert (root / "workspace" / "race.txt").read_bytes() == b"racer"


def test_bind_present_returns_exact_dict(tmp_path):
    guard, root = make_guard(tmp_path)
    binding = guard.bind_present("workspace/file.txt")
    assert binding == {
        "path": "workspace/file.txt",
        "sha256": hashlib.sha256(b"hello\n").hexdigest(),
        "size": 6,
        "state": "present",
    }


def test_b64u_create_end_to_end(tmp_path):
    guard, root = make_guard(tmp_path)
    data = b"payload bytes"
    request_params = {"content_b64": b64u_encode(data)}
    sha = hashlib.sha256(data).hexdigest()
    binding = guard.bind_absent("workspace/b64.txt", sha, len(data))
    from mgk.crypto import b64u_decode

    raw = b64u_decode(request_params["content_b64"])
    assert guard.create_bound(binding, raw) == sha
    assert (root / "workspace" / "b64.txt").read_bytes() == data