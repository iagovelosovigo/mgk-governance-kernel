"""Arrow Level 1: select the coherent route with least entropic resistance."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ArrowRoute:
    route_id: str
    coherence_delta: int
    entropic_resistance: int
    systemic_pressure: int
    threshold_k: int


class ArrowRouter:
    def select(self, routes: list[ArrowRoute]) -> ArrowRoute | None:
        eligible: list[ArrowRoute] = []
        for route in routes:
            values = (
                route.coherence_delta,
                route.entropic_resistance,
                route.systemic_pressure,
                route.threshold_k,
            )
            if not route.route_id or any(type(value) is not int for value in values):
                raise ValueError("invalid Arrow route")
            if route.entropic_resistance < 0 or route.systemic_pressure < 0 or route.threshold_k < 0:
                raise ValueError("Arrow pressure values must be non-negative")
            if route.coherence_delta >= 0 and route.systemic_pressure <= route.threshold_k:
                eligible.append(route)
        if not eligible:
            return None
        return min(
            eligible,
            key=lambda item: (
                item.entropic_resistance,
                -item.coherence_delta,
                item.systemic_pressure,
                item.route_id,
            ),
        )
