from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from urlchecker.feed_store import FeedMatch

Classification = Literal["malicious", "benign", "uncertain"]
Confidence = Literal["high", "medium", "low"]
DecisionSource = Literal["threat_feed", "machine_learning", "combined"]


@dataclass(frozen=True, slots=True)
class Decision:
    classification: Classification
    threat_type: str | None
    malicious_probability: float
    confidence: Confidence
    decision_source: DecisionSource
    requires_analyst_review: bool


def make_decision(
    *,
    probability: float,
    feed_matches: list[FeedMatch],
    malicious_threshold: float,
    benign_threshold: float,
) -> Decision:
    if feed_matches:
        threat_types = {match.threat_type for match in feed_matches}
        threat_type = next(iter(threat_types)) if len(threat_types) == 1 else "multiple"
        source: DecisionSource = "combined" if probability >= malicious_threshold else "threat_feed"
        return Decision(
            classification="malicious",
            threat_type=threat_type,
            malicious_probability=max(probability, 0.999),
            confidence="high",
            decision_source=source,
            requires_analyst_review=False,
        )

    if probability >= malicious_threshold:
        return Decision(
            classification="malicious",
            threat_type="unknown",
            malicious_probability=probability,
            confidence="high" if probability >= 0.95 else "medium",
            decision_source="machine_learning",
            requires_analyst_review=probability < 0.95,
        )

    if probability <= benign_threshold:
        return Decision(
            classification="benign",
            threat_type=None,
            malicious_probability=probability,
            confidence="high" if probability <= 0.05 else "medium",
            decision_source="machine_learning",
            requires_analyst_review=False,
        )

    return Decision(
        classification="uncertain",
        threat_type=None,
        malicious_probability=probability,
        confidence="low",
        decision_source="machine_learning",
        requires_analyst_review=True,
    )
