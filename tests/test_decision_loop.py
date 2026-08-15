from mgk import ArrowRoute, ArrowRouter, CHAAdapter, CHAInput, FeedbackEngine

from .helpers import read_request


def test_cha_has_no_authority():
    proposal = CHAAdapter().propose(
        read_request(),
        CHAInput(9000, 8000, 8500, 1000, 7000),
    )
    assert proposal.intelligence_only is True
    assert not hasattr(proposal, "capability")
    assert not hasattr(proposal, "execute")


def test_arrow_selects_least_resistance_eligible_route():
    routes = [
        ArrowRoute("short-forced", 500, 100, 101, 100),
        ArrowRoute("harmonic-b", 200, 20, 20, 100),
        ArrowRoute("harmonic-a", 100, 10, 30, 100),
    ]
    selected = ArrowRouter().select(routes)
    assert selected.route_id == "harmonic-a"


def test_arrow_returns_none_when_no_route_preserves_coherence():
    routes = [
        ArrowRoute("negative", -1, 1, 1, 10),
        ArrowRoute("pressure", 10, 1, 11, 10),
    ]
    assert ArrowRouter().select(routes) is None


def test_feedback_is_bounded_and_has_zero_authority_effect():
    feedback = FeedbackEngine()
    for _ in range(100):
        weights = feedback.record("TEN_XEITO", True, "OK")
        assert sum(weights) == 10000
        assert min(weights) >= 1000
    assert all(item["authority_effect"] == 0 for item in feedback.history)
