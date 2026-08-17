"""Sandbox actuator registry: the closed set of governed actions.

Each actuator maps a request to a concrete capability action and documents the
resource namespace it governs. Actuators never act on their own: a proposal is
data-only until the kernel issues a scoped capability and the executor runs it.
"""

from __future__ import annotations

from dataclasses import dataclass

ACTUATOR_ACTIONS = frozenset(
    {
        "sandbox.read_file",
        "sandbox.write_file",
        "sandbox.append_file",
        "sandbox.create_record",
        "sandbox.read_record",
    }
)


@dataclass(frozen=True)
class Actuator:
    action: str
    namespace: str
    description: str
    needs_content: bool = False


ACTUATORS = frozenset(
    {
        Actuator(
            "sandbox.read_file",
            "files/",
            "Read a file's bytes from the runtime workspace",
        ),
        Actuator(
            "sandbox.write_file",
            "files/",
            "Create or overwrite a file in the runtime workspace",
            needs_content=True,
        ),
        Actuator(
            "sandbox.append_file",
            "files/",
            "Append bytes to an existing file in the runtime workspace",
            needs_content=True,
        ),
        Actuator(
            "sandbox.create_record",
            "records/",
            "Create a structured record in the runtime records store",
            needs_content=True,
        ),
        Actuator(
            "sandbox.read_record",
            "records/",
            "Read a structured record from the runtime records store",
        ),
    }
)


def actuator_for(action: str) -> Actuator | None:
    for actuator in ACTUATORS:
        if actuator.action == action:
            return actuator
    return None


def validate_request(request: dict) -> None:
    """Validate a proposal shape against the closed actuator registry."""
    action = request.get("action")
    resource = request.get("resource")
    actuator = actuator_for(action)
    if actuator is None:
        raise ValueError("action is not a governed sandbox actuator")
    if not isinstance(resource, str) or not resource.startswith(actuator.namespace):
        raise ValueError(f"resource must live under {actuator.namespace!r}")
    parameters = request.get("parameters")
    if not isinstance(parameters, dict):
        raise ValueError("parameters must be a mapping")
    if actuator.needs_content and "content_b64" not in parameters:
        raise ValueError("actuator requires content_b64 parameter")
    if not actuator.needs_content and parameters:
        raise ValueError("actuator takes no content parameters")