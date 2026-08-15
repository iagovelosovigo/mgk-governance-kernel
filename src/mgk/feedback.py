"""Bounded Level 1 feedback; it cannot mint or verify capabilities."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class FeedbackEngine:
    weights: list[int] = field(default_factory=lambda: [4000, 3000, 3000])
    history: list[dict[str, object]] = field(default_factory=list)

    def __post_init__(self) -> None:
        if len(self.weights) != 3 or any(type(value) is not int or value < 1000 for value in self.weights):
            raise ValueError("invalid feedback weights")
        if sum(self.weights) != 10000:
            raise ValueError("feedback weights must total 10000")

    def record(self, result: str, successful: bool, reason_code: str) -> tuple[int, int, int]:
        if result not in {"TEN_XEITO", "REQUIRE_XEITO", "NON_TEN_XEITO"}:
            raise ValueError("invalid SAXP result")
        if type(successful) is not bool or not reason_code:
            raise ValueError("invalid feedback event")
        delta = 50
        proposed = list(self.weights)
        if result == "TEN_XEITO" and successful:
            proposed[2] += delta
            proposed[1] -= delta
        elif result == "NON_TEN_XEITO" or not successful:
            proposed[0] += delta
            proposed[2] -= delta
        else:
            proposed[1] += delta
            proposed[2] -= delta
        if min(proposed) < 1000:
            proposed = list(self.weights)
        self.weights[:] = proposed
        self.history.append(
            {
                "authority_effect": 0,
                "reason_code": reason_code,
                "result": result,
                "successful": successful,
                "weights": list(self.weights),
            }
        )
        return tuple(self.weights)
