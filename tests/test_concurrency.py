from concurrent.futures import ThreadPoolExecutor

import pytest

from .helpers import read_request


@pytest.mark.concurrency
@pytest.mark.timeout(30)
def test_concurrent_replay_has_exactly_one_execution(kernel_factory):
    kernel = kernel_factory()
    request = read_request()
    issued = kernel.authority.issue(request)
    with ThreadPoolExecutor(max_workers=16) as pool:
        results = list(pool.map(lambda _index: kernel.executor.execute(issued.envelope, request), range(32)))
    assert sum(result.success for result in results) == 1
    assert sum(result.execution_authority for result in results) == 1
    assert kernel.state.nonce_count() == 1


@pytest.mark.concurrency
@pytest.mark.timeout(30)
def test_independent_nonces_all_execute(kernel_factory):
    kernel = kernel_factory()
    requests = [read_request(f"request-{index}") for index in range(20)]
    envelopes = [kernel.authority.issue(request).envelope for request in requests]
    with ThreadPoolExecutor(max_workers=10) as pool:
        results = list(pool.map(lambda pair: kernel.executor.execute(pair[0], pair[1]), zip(envelopes, requests)))
    assert all(result.success for result in results)
    assert kernel.state.nonce_count() == len(requests)
