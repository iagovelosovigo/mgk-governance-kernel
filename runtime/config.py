"""Runtime configuration for the Functional Governance Runtime."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class RuntimeConfig:
    workdir: Path
    port: int = 8787
    host: str = "127.0.0.1"
    ttl_seconds: int = 60
    epoch: int = 1

    @classmethod
    def from_workdir(cls, workdir: str | Path, **overrides: object) -> "RuntimeConfig":
        path = Path(workdir).expanduser().resolve()
        port = overrides.get("port", 8787)
        host = overrides.get("host", "127.0.0.1")
        ttl = overrides.get("ttl_seconds", 60)
        epoch = overrides.get("epoch", 1)
        if not isinstance(port, int) or not 1024 <= port <= 65535:
            raise ValueError("invalid runtime port")
        if not isinstance(host, str) or not host:
            raise ValueError("invalid runtime host")
        if not isinstance(ttl, int) or not 1 <= ttl <= 300:
            raise ValueError("invalid runtime TTL")
        if not isinstance(epoch, int) or epoch < 1:
            raise ValueError("invalid runtime epoch")
        return cls(workdir=path, port=port, host=host, ttl_seconds=ttl, epoch=epoch)