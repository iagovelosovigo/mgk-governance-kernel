"""CHA Level 1: proposal intelligence with zero execution authority."""

from __future__ import annotations

from dataclasses import dataclass

from .models import ActionRequest


@dataclass(frozen=True)
class CHAInput:
    reptile_integrity: int
    limbic_resonance: int
    cognitive_coherence: int
    dissonance: int
    experience: int


@dataclass(frozen=True)
class CHAProposal:
    request: ActionRequest
    score: int
    intelligence_only: bool
    components: dict[str, int]


class CHAAdapter:
    """Deterministic integer scoring; the result is only a proposal."""

    def __init__(self, weights: tuple[int, int, int] = (4000, 3000, 3000)):
        if len(weights) != 3 or any(type(item) is not int or item < 0 for item in weights):
            raise ValueError("invalid CHA weights")
        if sum(weights) != 10000:
            raise ValueError("CHA weights must total 10000")
        self.weights = weights

    def propose(self, request: ActionRequest, inputs: CHAInput) -> CHAProposal:
        values = (
            inputs.reptile_integrity,
            inputs.limbic_resonance,
            inputs.cognitive_coherence,
            inputs.dissonance,
            inputs.experience,
        )
        if any(type(value) is not int or not 0 <= value <= 10000 for value in values):
            raise ValueError("CHA inputs must be integer basis points")
        integrated = (
            inputs.reptile_integrity
            + inputs.limbic_resonance
            + inputs.cognitive_coherence
        ) // 3
        score = (
            self.weights[0] * integrated
            - self.weights[1] * inputs.dissonance
            + self.weights[2] * inputs.experience
        ) // 10000
        score = max(-10000, min(10000, score))
        return CHAProposal(
            request=request,
            score=score,
            intelligence_only=True,
            components={
                "cognitive_coherence": inputs.cognitive_coherence,
                "dissonance": inputs.dissonance,
                "experience": inputs.experience,
                "integrated": integrated,
                "limbic_resonance": inputs.limbic_resonance,
                "reptile_integrity": inputs.reptile_integrity,
            },
        )
