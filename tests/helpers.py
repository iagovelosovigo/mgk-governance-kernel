from __future__ import annotations

from mgk import ActionRequest


def read_request(request_id="request-1", resource="workspace/allowed.txt", principal="planner", audience="executor"):
    return ActionRequest(
        request_id=request_id,
        principal=principal,
        audience=audience,
        action="resource.read",
        resource=resource,
        parameters={},
    )
