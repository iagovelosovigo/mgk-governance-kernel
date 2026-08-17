"""POLICY_PRESERVATION probe for mgk.authority.xǁCapabilityAuthorityǁ__init____mutmut_14.

Mutation: self.policy = policy or AuthorityPolicy()  ->  policy and AuthorityPolicy()

A caller that supplies no policy must receive the safe default, never None.
"""
import json
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from mgk import ResourceGuard
from mgk.state import SecurityState


def build_authority():
    key = Ed25519PrivateKey.generate()
    tmp = Path(tempfile.mkdtemp())
    state = SecurityState(tmp / "state.sqlite", key.public_key())
    state.initialize_epoch(1, key)
    root = tmp / "resources"
    (root / "workspace").mkdir(parents=True)
    guard = ResourceGuard(root)
    from mgk.saxp import SAXPContext
    ctx = lambda request: SAXPContext(
        coherence_delta=0, systemic_pressure=0, threshold_k=10, sentidino=9000,
        information_complete=True, critical_uncertainty=False, control_risk=False,
        ethical_constraints_satisfied=True,
    )
    from mgk.authority import CapabilityAuthority
    return CapabilityAuthority(
        issuer="mgk.test", private_key=key, state=state, resource_guard=guard,
        context_provider=ctx, policy=None,
    )


try:
    auth = build_authority()
    policy_ok = auth.policy is not None and getattr(auth.policy, "policy_id", None) == "mgk-authority-v1"
    print("RESULT_JSON=" + json.dumps({"policy_preserved": bool(policy_ok), "policy_id": getattr(auth.policy, "policy_id", None)}))
except Exception as exc:  # noqa: BLE001
    print("RESULT_JSON=" + json.dumps({"policy_preserved": False, "error": f"{type(exc).__name__}: {exc}"}))