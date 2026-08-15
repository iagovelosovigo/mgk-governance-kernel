"""Resource binding and descriptor-based anti-TOCTOU operations."""

from __future__ import annotations

import hashlib
import os
import re
import stat
from pathlib import Path, PurePosixPath

from .errors import ResourceError

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
MAX_RESOURCE_BYTES = 8 * 1024 * 1024


class ResourceGuard:
    def __init__(self, root: str | Path):
        path = Path(root)
        if path.is_symlink() or not path.is_dir():
            raise ResourceError("resource root must be a real directory")
        self.root = path.resolve(strict=True)

    @staticmethod
    def _parts(relative: str) -> tuple[str, ...]:
        if type(relative) is not str or not relative or len(relative.encode("utf-8")) > 4096:
            raise ResourceError("invalid resource path")
        if "\\" in relative or "\x00" in relative:
            raise ResourceError("non-portable resource path")
        raw_parts = relative.split("/")
        if any(part in {"", ".", ".."} for part in raw_parts):
            raise ResourceError("path traversal is forbidden")
        path = PurePosixPath(relative)
        if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
            raise ResourceError("path traversal is forbidden")
        if len(path.parts) > 32:
            raise ResourceError("resource path is too deep")
        return path.parts

    def _open_parent(self, relative: str) -> tuple[int, str]:
        parts = self._parts(relative)
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        current = os.open(self.root, flags)
        try:
            for part in parts[:-1]:
                following = os.open(part, flags, dir_fd=current)
                os.close(current)
                current = following
            return current, parts[-1]
        except BaseException:
            os.close(current)
            raise

    def _open_file(self, relative: str) -> int:
        parent, name = self._open_parent(relative)
        try:
            flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(name, flags, dir_fd=parent)
        except OSError as exc:
            raise ResourceError(f"cannot open bound resource: {exc.strerror}") from exc
        finally:
            os.close(parent)
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            os.close(descriptor)
            raise ResourceError("bound resource is not a regular file")
        if info.st_size > MAX_RESOURCE_BYTES:
            os.close(descriptor)
            raise ResourceError("bound resource exceeds size limit")
        return descriptor

    @staticmethod
    def _read_descriptor(descriptor: int) -> bytes:
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_RESOURCE_BYTES:
                raise ResourceError("bound resource exceeds size limit")
            chunks.append(chunk)
        return b"".join(chunks)

    def bind_present(self, relative: str) -> dict[str, object]:
        descriptor = self._open_file(relative)
        try:
            data = self._read_descriptor(descriptor)
        finally:
            os.close(descriptor)
        return {
            "path": relative,
            "sha256": hashlib.sha256(data).hexdigest(),
            "size": len(data),
            "state": "present",
        }

    def bind_absent(self, relative: str, post_sha256: str, post_size: int) -> dict[str, object]:
        if not _SHA256.fullmatch(post_sha256) or type(post_size) is not int:
            raise ResourceError("invalid post-state binding")
        if not 0 <= post_size <= MAX_RESOURCE_BYTES:
            raise ResourceError("invalid post-state size")
        parent, name = self._open_parent(relative)
        try:
            try:
                os.stat(name, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise ResourceError("create target already exists")
        finally:
            os.close(parent)
        return {
            "path": relative,
            "post_sha256": post_sha256,
            "post_size": post_size,
            "state": "absent",
        }

    def read_bound(self, binding: dict[str, object]) -> bytes:
        if set(binding) != {"path", "sha256", "size", "state"} or binding["state"] != "present":
            raise ResourceError("invalid present-resource binding")
        descriptor = self._open_file(binding["path"])
        try:
            data = self._read_descriptor(descriptor)
        finally:
            os.close(descriptor)
        if len(data) != binding["size"] or hashlib.sha256(data).hexdigest() != binding["sha256"]:
            raise ResourceError("resource changed after authorization")
        return data

    def create_bound(self, binding: dict[str, object], data: bytes) -> str:
        if set(binding) != {"path", "post_sha256", "post_size", "state"}:
            raise ResourceError("invalid absent-resource binding")
        if binding["state"] != "absent" or type(data) is not bytes:
            raise ResourceError("invalid create request")
        digest = hashlib.sha256(data).hexdigest()
        if len(data) != binding["post_size"] or digest != binding["post_sha256"]:
            raise ResourceError("create payload does not match capability binding")
        if len(data) > MAX_RESOURCE_BYTES:
            raise ResourceError("create payload exceeds size limit")
        parent, name = self._open_parent(binding["path"])
        descriptor: int | None = None
        created = False
        try:
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(name, flags, 0o600, dir_fd=parent)
            created = True
            view = memoryview(data)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise ResourceError("short write while creating resource")
                view = view[written:]
            os.fsync(descriptor)
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_size != len(data):
                raise ResourceError("created resource verification failed")
            os.close(descriptor)
            descriptor = None
            os.fsync(parent)
            return digest
        except FileExistsError as exc:
            raise ResourceError("create target appeared after authorization") from exc
        except BaseException:
            if descriptor is not None:
                os.close(descriptor)
            if created:
                try:
                    os.unlink(name, dir_fd=parent)
                    os.fsync(parent)
                except OSError:
                    pass
            raise
        finally:
            os.close(parent)

    def remove_created(self, binding: dict[str, object], digest: str) -> bool:
        """Rollback a just-created target only if it is still the bound regular file."""
        if binding.get("state") != "absent" or binding.get("post_sha256") != digest:
            return False
        parent, name = self._open_parent(binding["path"])
        descriptor: int | None = None
        try:
            descriptor = os.open(name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=parent)
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode):
                return False
            data = self._read_descriptor(descriptor)
            if len(data) != binding["post_size"] or hashlib.sha256(data).hexdigest() != digest:
                return False
            os.close(descriptor)
            descriptor = None
            os.unlink(name, dir_fd=parent)
            os.fsync(parent)
            return True
        except OSError:
            return False
        finally:
            if descriptor is not None:
                os.close(descriptor)
            os.close(parent)
