"""Workspace: builds the full kernel + runtime object graph and persists keys/state."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from mgk.authority import AuthorityPolicy, CapabilityAuthority, SANDBOX_ACTIONS
from mgk.clock import SystemClock
from mgk.crypto import (
    generate_private_key,
    key_id,
    load_private_key,
    load_public_key,
    private_key_bytes,
    public_key_bytes,
)
from mgk.executor import CapabilityExecutor
from mgk.ledger import AuditLedger, FailureLedger
from mgk.resource import ResourceGuard
from mgk.state import SecurityState
from mgk.verifier import CapabilityVerifier

from .config import RuntimeConfig
from .decision import DecisionPipeline
from .flight import FlightRecorder
from .policy import RuntimePolicy
from .runtime_ledger import RuntimeLedger


class Workspace:
    """A running runtime's on-disk home: keys, state, ledgers, sandbox.

    The workspace root is gitignored; private keys are generated locally and
    never leave the machine or the repository.
    """

    def __init__(self, config: RuntimeConfig):
        self.config = config
        self.workdir = config.workdir
        self.root = self.workdir / ".mgk"
        self.keys_dir = self.root / "keys"
        self.state_path = self.root / "security.sqlite"
        self.audit_path = self.root / "audit.jsonl"
        self.audit_checkpoint = self.root / "audit.checkpoint.json"
        self.failures_path = self.root / "failures.jsonl"
        self.failures_checkpoint = self.root / "failures.checkpoint.json"
        self.flight_path = self.root / "flight.jsonl"
        self.flight_checkpoint = self.root / "flight.checkpoint.json"
        self.ledger_path = self.root / "runtime.sqlite"
        self.sandbox_root = self.root / "sandbox"
        self.files_root = self.sandbox_root / "files"
        self.records_root = self.sandbox_root / "records"
        self._ensure_dirs()

    def _ensure_dirs(self) -> None:
        for directory in (
            self.root,
            self.keys_dir,
            self.files_root,
            self.records_root,
        ):
            directory.mkdir(parents=True, exist_ok=True)
        for directory in (self.root, self.keys_dir):
            os.chmod(directory, 0o700)

    @property
    def initialized(self) -> bool:
        authority_path = self.keys_dir / "authority.key"
        return authority_path.exists()

    def _load_or_generate_key(self, name: str) -> Ed25519PrivateKey:
        path = self.keys_dir / f"{name}.key"
        if path.exists():
            raw = path.read_bytes()
            if len(raw) != 32:
                raise ValueError(f"corrupt {name} key")
            return load_private_key(raw)
        key = generate_private_key()
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.write(descriptor, private_key_bytes(key))
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        return key

    def _public_key(self, key: Ed25519PrivateKey):
        return key.public_key()

    def _write_identity(self, path: str, key: Ed25519PrivateKey) -> None:
        (self.keys_dir / f"{path}.pub").write_text(key_id(self._public_key(key)) + "\n")

    def _identity(self) -> dict[str, Any]:
        return {
            "authority": (self.keys_dir / "authority.pub").read_text().strip(),
            "audit": (self.keys_dir / "audit.pub").read_text().strip(),
            "operator": (self.keys_dir / "operator.pub").read_text().strip(),
        }

    def create_runtime(self, policy: RuntimePolicy | None = None) -> "RuntimeBundle":
        authority_key = self._load_or_generate_key("authority")
        audit_key = self._load_or_generate_key("audit")
        operator_key = self._load_or_generate_key("operator")
        self._write_identity("authority", authority_key)
        self._write_identity("audit", audit_key)
        self._write_identity("operator", operator_key)

        clock = SystemClock()
        state = SecurityState(self.state_path, authority_key.public_key(), 1)
        try:
            state.current_epoch()
        except Exception:
            state.initialize_epoch(1, authority_key)

        guard = ResourceGuard(self.sandbox_root)
        runtime_policy = policy or RuntimePolicy()
        effective_actions = frozenset(SANDBOX_ACTIONS) | runtime_policy.allowed_actions
        authority_policy = AuthorityPolicy(
            allowed_actions=effective_actions,
            allowed_principals=frozenset({"planner"}),
            allowed_audiences=frozenset({"executor"}),
            allowed_resource_prefixes=runtime_policy.allowed_resource_prefixes,
            default_ttl_seconds=self.config.ttl_seconds,
            maximum_ttl_seconds=300,
        )
        authority_policy.validate()

        def context_provider(request):
            return runtime_policy.context_for(request)

        authority = CapabilityAuthority(
            "runtime-authority",
            authority_key,
            state,
            guard,
            context_provider,
            policy=authority_policy,
            clock=clock,
        )
        verifier = CapabilityVerifier(authority_key.public_key(), state, clock=clock)
        audit = AuditLedger(
            self.audit_path,
            self.audit_checkpoint,
            audit_key.public_key(),
            audit_key,
        )
        failures = FailureLedger(
            self.failures_path,
            self.failures_checkpoint,
            audit_key.public_key(),
            audit_key,
        )
        executor = CapabilityExecutor("executor", verifier, guard, audit, failures, clock)
        flight = FlightRecorder(self.flight_path, self.flight_checkpoint)
        ledger = RuntimeLedger(self.ledger_path)
        for path in (self.state_path, self.ledger_path):
            os.chmod(path, 0o600)
        pipeline = DecisionPipeline(
            authority,
            verifier,
            executor,
            runtime_policy,
            flight,
            ledger,
            operator_key=operator_key,
            clock=clock,
        )
        return RuntimeBundle(
            workspace=self,
            authority=authority,
            verifier=verifier,
            executor=executor,
            state=state,
            audit=audit,
            failures=failures,
            flight=flight,
            ledger=ledger,
            pipeline=pipeline,
            guard=guard,
            operator_key=operator_key,
            identity=self._identity(),
        )


class RuntimeBundle:
    def __init__(self, **kwargs: Any):
        self.workspace: Workspace = kwargs["workspace"]
        self.authority: CapabilityAuthority = kwargs["authority"]
        self.verifier: CapabilityVerifier = kwargs["verifier"]
        self.executor: CapabilityExecutor = kwargs["executor"]
        self.state: SecurityState = kwargs["state"]
        self.audit: AuditLedger = kwargs["audit"]
        self.failures: FailureLedger = kwargs["failures"]
        self.flight: FlightRecorder = kwargs["flight"]
        self.ledger: RuntimeLedger = kwargs["ledger"]
        self.pipeline: DecisionPipeline = kwargs["pipeline"]
        self.guard: ResourceGuard = kwargs["guard"]
        self.operator_key: Ed25519PrivateKey = kwargs["operator_key"]
        self.identity: dict[str, Any] = kwargs["identity"]

    def status(self) -> dict[str, Any]:
        return {
            "workdir": str(self.workspace.workdir),
            "version": "0.2.0",
            "epoch": self.state.current_epoch(),
            "nonce_count": self.state.nonce_count(),
            "audit_head": self.audit.verify_integrity()[1],
            "flight_head": self.flight.verify_integrity()[1],
            "decision_count": len(self.ledger.decisions()),
            "human_action_count": len(self.ledger.human_actions()),
            "identity": self.identity,
        }