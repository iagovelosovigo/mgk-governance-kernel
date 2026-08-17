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


def test_bind_write_absent_exact_dict(tmp_path):
    guard, root = make_guard(tmp_path)
    data = b"new bytes\n"
    binding = guard.bind_write("workspace/w.txt", data)
    assert binding == {
        "path": "workspace/w.txt",
        "post_sha256": hashlib.sha256(data).hexdigest(),
        "post_size": len(data),
        "pre_sha256": "",
        "pre_size": 0,
        "pre_state": "absent",
        "state": "write",
    }


def test_bind_write_present_exact_dict(tmp_path):
    guard, root = make_guard(tmp_path)
    data = b"replacement\n"
    pre = b"hello\n"
    binding = guard.bind_write("workspace/file.txt", data)
    assert binding == {
        "path": "workspace/file.txt",
        "post_sha256": hashlib.sha256(data).hexdigest(),
        "post_size": len(data),
        "pre_sha256": hashlib.sha256(pre).hexdigest(),
        "pre_size": len(pre),
        "pre_state": "present",
        "state": "write",
    }


def test_bind_write_rejects_oversize_and_non_bytes(tmp_path):
    from mgk.resource import MAX_RESOURCE_BYTES

    guard, root = make_guard(tmp_path)
    with pytest.raises(ResourceError, match="^invalid write payload size$"):
        guard.bind_write("workspace/big.txt", b"x" * (MAX_RESOURCE_BYTES + 1))
    with pytest.raises(ResourceError, match="^invalid write payload size$"):
        guard.bind_write("workspace/big.txt", "text")


def test_write_bound_absent_creates_exact(tmp_path):
    guard, root = make_guard(tmp_path)
    data = b"created via write\n"
    binding = guard.bind_write("workspace/wc.txt", data)
    assert guard.write_bound(binding, data) == binding["post_sha256"]
    target = root / "workspace" / "wc.txt"
    assert target.read_bytes() == data
    assert target.stat().st_mode & 0o777 == 0o600


def test_write_bound_absent_race_fails_closed(tmp_path):
    guard, root = make_guard(tmp_path)
    data = b"abc"
    binding = guard.bind_write("workspace/wr.txt", data)
    (root / "workspace" / "wr.txt").write_bytes(b"racer")
    with pytest.raises(ResourceError, match="^write target appeared after authorization$"):
        guard.write_bound(binding, data)
    assert (root / "workspace" / "wr.txt").read_bytes() == b"racer"


def test_write_bound_present_overwrites_exact(tmp_path):
    guard, root = make_guard(tmp_path)
    data = b"overwritten\n"
    binding = guard.bind_write("workspace/file.txt", data)
    assert guard.write_bound(binding, data) == binding["post_sha256"]
    assert (root / "workspace" / "file.txt").read_bytes() == data
    assert (root / "workspace" / "file.txt").read_bytes() == b"overwritten\n"


def test_write_bound_present_changed_pre_fails(tmp_path):
    guard, root = make_guard(tmp_path)
    data = b"x"
    binding = guard.bind_write("workspace/file.txt", data)
    (root / "workspace" / "file.txt").write_bytes(b"tampered\n")
    with pytest.raises(ResourceError, match="^write target changed after authorization$"):
        guard.write_bound(binding, data)


def test_write_bound_rejects_invalid_binding_and_payload(tmp_path):
    guard, root = make_guard(tmp_path)
    data = b"x"
    binding = guard.bind_write("workspace/wb.txt", data)
    with pytest.raises(ResourceError, match="^invalid write-resource binding$"):
        bad = dict(binding)
        bad.pop("state")
        guard.write_bound(bad, data)
    with pytest.raises(ResourceError, match="^invalid write-resource binding$"):
        bad = dict(binding)
        bad["state"] = "append"
        guard.write_bound(bad, data)
    with pytest.raises(ResourceError, match="^invalid write pre-state$"):
        bad = dict(binding)
        bad["pre_state"] = "bogus"
        guard.write_bound(bad, data)
    with pytest.raises(ResourceError, match="^write payload does not match capability binding$"):
        guard.write_bound(binding, b"y")
    with pytest.raises(ResourceError, match="^write payload exceeds size limit$"):
        from mgk.resource import MAX_RESOURCE_BYTES

        guard.write_bound(binding, b"y" * (MAX_RESOURCE_BYTES + 1))


def test_bind_append_exact_dict(tmp_path):
    guard, root = make_guard(tmp_path)
    pre = b"hello\n"
    data = b"appended\n"
    binding = guard.bind_append("workspace/file.txt", data)
    assert binding == {
        "path": "workspace/file.txt",
        "post_sha256": hashlib.sha256(pre + data).hexdigest(),
        "post_size": len(pre + data),
        "pre_sha256": hashlib.sha256(pre).hexdigest(),
        "pre_size": len(pre),
        "state": "append",
    }


def test_bind_append_rejects_oversize(tmp_path):
    from mgk.resource import MAX_RESOURCE_BYTES

    guard, root = make_guard(tmp_path)
    with pytest.raises(ResourceError, match="^invalid append payload size$"):
        guard.bind_append("workspace/file.txt", b"x" * (MAX_RESOURCE_BYTES + 1))


def test_append_bound_appends_exact(tmp_path):
    guard, root = make_guard(tmp_path)
    data = b"more\n"
    binding = guard.bind_append("workspace/file.txt", data)
    assert guard.append_bound(binding, data) == binding["post_sha256"]
    assert (root / "workspace" / "file.txt").read_bytes() == b"hello\nmore\n"


def test_append_bound_missing_target_fails(tmp_path):
    guard, root = make_guard(tmp_path)
    data = b"x"
    binding = guard.bind_append("workspace/file.txt", data)
    (root / "workspace" / "file.txt").unlink()
    with pytest.raises(ResourceError, match="^append target is missing$"):
        guard.append_bound(binding, data)


def test_append_bound_changed_pre_fails(tmp_path):
    guard, root = make_guard(tmp_path)
    data = b"x"
    binding = guard.bind_append("workspace/file.txt", data)
    (root / "workspace" / "file.txt").write_bytes(b"changed\n")
    with pytest.raises(ResourceError, match="^append target changed after authorization$"):
        guard.append_bound(binding, data)


def test_append_bound_rejects_invalid_binding(tmp_path):
    guard, root = make_guard(tmp_path)
    data = b"x"
    binding = guard.bind_append("workspace/file.txt", data)
    with pytest.raises(ResourceError, match="^invalid append-resource binding$"):
        bad = dict(binding)
        bad.pop("path")
        guard.append_bound(bad, data)
    with pytest.raises(ResourceError, match="^invalid append-resource binding$"):
        bad = dict(binding)
        bad["state"] = "write"
        guard.append_bound(bad, data)
    with pytest.raises(ResourceError, match="^append payload exceeds size limit$"):
        from mgk.resource import MAX_RESOURCE_BYTES

        guard.append_bound(binding, b"x" * (MAX_RESOURCE_BYTES + 1))


def test_bind_write_target_directory_rejects_exact_error(tmp_path):
    guard, root = make_guard(tmp_path)
    with pytest.raises(ResourceError, match="^write target is not a regular file$"):
        guard.bind_write("workspace", b"x")


def test_bind_write_broken_symlink_target_rejects(tmp_path):
    guard, root = make_guard(tmp_path)
    (root / "workspace" / "link.txt").symlink_to("missing-target")
    with pytest.raises(OSError):
        guard.bind_write("workspace/link.txt", b"x")


def test_bind_append_pre_plus_data_over_limit_rejects_exact_error(tmp_path):
    from mgk.resource import MAX_RESOURCE_BYTES

    guard, root = make_guard(tmp_path)
    (root / "workspace" / "big.txt").write_bytes(b"x" * MAX_RESOURCE_BYTES)
    with pytest.raises(ResourceError, match="^append result exceeds size limit$"):
        guard.bind_append("workspace/big.txt", b"y")


def test_bind_append_exact_limit_succeeds(tmp_path):
    from mgk.resource import MAX_RESOURCE_BYTES

    guard, root = make_guard(tmp_path)
    (root / "workspace" / "empty.txt").write_bytes(b"")
    binding = guard.bind_append("workspace/empty.txt", b"x" * MAX_RESOURCE_BYTES)
    assert binding["post_size"] == MAX_RESOURCE_BYTES
    assert binding["pre_size"] == 0


def test_bind_write_exact_limit_succeeds(tmp_path):
    from mgk.resource import MAX_RESOURCE_BYTES

    guard, root = make_guard(tmp_path)
    binding = guard.bind_write("workspace/big.txt", b"x" * MAX_RESOURCE_BYTES)
    assert binding["post_size"] == MAX_RESOURCE_BYTES
    assert binding["pre_state"] == "absent"


def test_bind_present_exact_limit_succeeds(tmp_path):
    from mgk.resource import MAX_RESOURCE_BYTES

    guard, root = make_guard(tmp_path)
    (root / "workspace" / "big.txt").write_bytes(b"x" * MAX_RESOURCE_BYTES)
    binding = guard.bind_present("workspace/big.txt")
    assert binding["size"] == MAX_RESOURCE_BYTES


def test_bind_absent_max_size_succeeds(tmp_path):
    from mgk.resource import MAX_RESOURCE_BYTES

    guard, root = make_guard(tmp_path)
    data = b"x" * MAX_RESOURCE_BYTES
    binding = guard.bind_absent("workspace/max.txt", hashlib.sha256(data).hexdigest(), len(data))
    assert binding["post_size"] == MAX_RESOURCE_BYTES


def test_write_bound_exact_limit_succeeds(tmp_path):
    from mgk.resource import MAX_RESOURCE_BYTES

    guard, root = make_guard(tmp_path)
    data = b"x" * MAX_RESOURCE_BYTES
    binding = guard.bind_write("workspace/big.txt", data)
    assert guard.write_bound(binding, data) == binding["post_sha256"]
    assert (root / "workspace" / "big.txt").stat().st_size == MAX_RESOURCE_BYTES


def test_append_bound_exact_limit_succeeds(tmp_path):
    from mgk.resource import MAX_RESOURCE_BYTES

    guard, root = make_guard(tmp_path)
    (root / "workspace" / "empty.txt").write_bytes(b"")
    data = b"x" * MAX_RESOURCE_BYTES
    binding = guard.bind_append("workspace/empty.txt", data)
    assert guard.append_bound(binding, data) == binding["post_sha256"]
    assert (root / "workspace" / "empty.txt").stat().st_size == MAX_RESOURCE_BYTES


def test_write_bound_present_empty_data_truncates(tmp_path):
    guard, root = make_guard(tmp_path)
    data = b""
    binding = guard.bind_write("workspace/file.txt", data)
    assert guard.write_bound(binding, data) == binding["post_sha256"]
    assert (root / "workspace" / "file.txt").read_bytes() == b""


def test_write_bound_present_target_deleted_rejects(tmp_path):
    guard, root = make_guard(tmp_path)
    data = b"x"
    binding = guard.bind_write("workspace/file.txt", data)
    (root / "workspace" / "file.txt").unlink()
    with pytest.raises(OSError):
        guard.write_bound(binding, data)


def test_bind_absent_broken_symlink_target_rejects_exact_error(tmp_path):
    guard, root = make_guard(tmp_path)
    (root / "workspace" / "link.txt").symlink_to("missing-target")
    with pytest.raises(ResourceError, match="^create target already exists$"):
        guard.bind_absent("workspace/link.txt", hashlib.sha256(b"x").hexdigest(), 1)


def test_open_parent_midwalk_file_rejects(tmp_path):
    guard, root = make_guard(tmp_path)
    with pytest.raises(OSError):
        guard.bind_present("workspace/file.txt/child")


def test_remove_created_directory_target_returns_false(tmp_path):
    guard, root = make_guard(tmp_path)
    data = b"content\n"
    sha = hashlib.sha256(data).hexdigest()
    binding = guard.bind_absent("workspace/dir.txt", sha, len(data))
    guard.create_bound(binding, data)
    target = root / "workspace" / "dir.txt"
    target.unlink()
    target.mkdir()
    assert guard.remove_created(binding, sha) is False
    assert target.is_dir()


def test_remove_created_changed_content_returns_false(tmp_path):
    guard, root = make_guard(tmp_path)
    data = b"hello\n"
    sha = hashlib.sha256(data).hexdigest()
    binding = guard.bind_absent("workspace/swap.txt", sha, len(data))
    guard.create_bound(binding, data)
    target = root / "workspace" / "swap.txt"
    target.write_bytes(b"hallo\n")
    assert guard.remove_created(binding, sha) is False
    assert target.read_bytes() == b"hallo\n"