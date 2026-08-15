from __future__ import annotations

import os

import pytest
from hypothesis import given, settings, strategies as st

from api_contract import request
from tests.helpers import Counter, assert_denied


pytestmark = [pytest.mark.fuzz, pytest.mark.adversarial, pytest.mark.protected]


@given(st.binary(min_size=0, max_size=4096))
@settings(max_examples=500, deadline=None)
def test_arbitrary_capability_bytes_fail_closed(harness, blob):
    req = request()
    token = harness.import_capability(blob)
    counter = Counter()
    assert_denied(harness.execute(token, req, counter.operation), counter)


def test_deterministic_byte_fuzz_corpus_has_zero_accepts(harness):
    req = request()
    for length in (0, 1, 2, 7, 16, 31, 32, 63, 64, 127, 255, 1024, 4096):
        for fill in (b"\x00", b"\xff", b"{", b"[", b'"'):
            blob = (fill * max(1, length))[:length]
            token = harness.import_capability(blob)
            counter = Counter()
            assert_denied(harness.execute(token, req, counter.operation), counter)


def test_every_single_bit_signature_mutation_is_denied(harness):
    req = request()
    valid = harness.issue(req, nonce="n-bitflip-1")
    signature = bytearray(harness.signature(valid))
    assert signature
    for index in range(len(signature)):
        for bit in range(8):
            changed = bytearray(signature)
            changed[index] ^= 1 << bit
            forged = harness.assemble(harness.claims(valid), bytes(changed))
            counter = Counter()
            assert_denied(harness.execute(forged, req, counter.operation), counter)


def test_random_malformed_corpus_never_executes(harness):
    req = request()
    for _ in range(256):
        token = harness.import_capability(os.urandom(257))
        counter = Counter()
        assert_denied(harness.execute(token, req, counter.operation), counter)

