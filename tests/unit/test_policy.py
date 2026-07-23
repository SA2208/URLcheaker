from __future__ import annotations

from urlchecker.decision_policy import make_decision
from urlchecker.feed_store import FeedMatch


def test_feed_match_overrides_low_model_probability() -> None:
    decision = make_decision(
        probability=0.01,
        feed_matches=[FeedMatch("source", "1", "phishing")],
        malicious_threshold=0.8,
        benign_threshold=0.2,
    )
    assert decision.classification == "malicious"
    assert decision.decision_source == "threat_feed"
    assert decision.malicious_probability == 0.999


def test_intermediate_probability_is_uncertain() -> None:
    decision = make_decision(
        probability=0.5,
        feed_matches=[],
        malicious_threshold=0.8,
        benign_threshold=0.2,
    )
    assert decision.classification == "uncertain"
    assert decision.requires_analyst_review is True
