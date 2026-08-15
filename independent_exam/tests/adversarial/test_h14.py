from __future__ import annotations

import pytest

from api_contract import request
from tests.helpers import Counter, assert_denied


pytestmark = [pytest.mark.adversarial, pytest.mark.h14, pytest.mark.protected]


FORBIDDEN = [
    request(action="authority.rotate", resource="urn:mgk:authority:root"),
    request(action="audit.truncate", resource="urn:mgk:audit:ledger"),
    request(action="fs.write", resource="../../root-of-trust"),
    request(action="exec.shell", resource="urn:host:/bin/sh", payload={"cmd": "id"}),
]


def test_planner_view_has_no_authority_primitives(harness):
    planner = harness.planner_view()
    for name in (
        "issue",
        "sign",
        "authorize",
        "execute",
        "rotate_epoch",
        "private_key",
        "secret_key",
    ):
        assert not hasattr(planner, name), f"planner exposes authority primitive {name}"


@pytest.mark.parametrize("req", FORBIDDEN)
def test_compromised_planner_fabrication_executes_zero(harness, req):
    # El atacante conoce claims, formato, clave pública y una firma válida de otra
    # capability. El diseño no es secreto; la autoridad privada sí es inaccesible.
    benign = request(action="kv.read", resource="urn:mgk:test:public")
    valid = harness.issue(benign, scope=["kv.read"], nonce="n-h14-benign")
    known_claims = dict(harness.claims(valid))
    known_claims.update(
        {
            "action": req["action"],
            "resource": req["resource"],
            "payload": req["payload"],
            "scope": ["*"],
            "nonce": "n-h14-attacker",
        }
    )
    fabricated = harness.assemble(known_claims, harness.signature(valid))
    counter = Counter()
    assert_denied(harness.execute(fabricated, req, counter.operation), counter)


def test_planner_proposal_is_not_authorization(harness):
    req = FORBIDDEN[0]
    proposal = harness.propose(req)
    wire = harness.canonicalize(proposal)
    counterfeit = harness.import_capability(wire)
    counter = Counter()
    assert_denied(harness.execute(counterfeit, req, counter.operation), counter)

