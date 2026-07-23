from __future__ import annotations

from dataclasses import asdict
from datetime import UTC, datetime

from sqlalchemy.orm import Session

from urlchecker.config import Settings
from urlchecker.db_models import Analysis
from urlchecker.decision_policy import make_decision
from urlchecker.features import extract_features, feature_reasons
from urlchecker.feed_store import FeedStore
from urlchecker.model_service import Predictor
from urlchecker.repository import AnalysisRepository
from urlchecker.schemas import AnalysisResponse
from urlchecker.security import redact_url, sha256_text
from urlchecker.url_normalizer import normalize_url


class AnalysisService:
    def __init__(self, settings: Settings, predictor: Predictor, feed_store: FeedStore) -> None:
        self.settings = settings
        self.predictor = predictor
        self.feed_store = feed_store

    def analyze(self, raw_url: str, session: Session) -> AnalysisResponse:
        normalized = normalize_url(raw_url, max_length=self.settings.max_url_length)
        features = extract_features(normalized)
        feed_matches = self.feed_store.lookup(normalized.normalized)
        prediction = self.predictor.predict(features)
        decision = make_decision(
            probability=prediction.malicious_probability,
            feed_matches=feed_matches,
            malicious_threshold=self.settings.malicious_threshold,
            benign_threshold=self.settings.benign_threshold,
        )
        reasons = feature_reasons(features)
        if feed_matches:
            reasons.insert(
                0,
                {
                    "code": "KNOWN_THREAT_FEED_MATCH",
                    "description": "The normalized URL exactly matches a configured threat feed.",
                    "feature_name": "feed_match_count",
                    "feature_value": float(len(feed_matches)),
                },
            )

        display_url = (
            normalized.normalized
            if self.settings.store_full_urls
            else redact_url(normalized.normalized)
        )
        analysis = Analysis(
            display_url=display_url,
            normalized_url_hash=sha256_text(normalized.normalized),
            registrable_domain=normalized.registrable_domain,
            classification=decision.classification,
            threat_type=decision.threat_type,
            malicious_probability=decision.malicious_probability,
            confidence=decision.confidence,
            decision_source=decision.decision_source,
            requires_analyst_review=decision.requires_analyst_review,
            reasons=reasons,
            feed_matches=[asdict(match) for match in feed_matches],
            model_version=prediction.model_version,
            dataset_version=self.settings.dataset_version,
            model_backend=prediction.backend,
            created_at=datetime.now(UTC),
        )
        saved = AnalysisRepository(session).add(analysis)
        return analysis_to_response(saved)


def analysis_to_response(analysis: Analysis) -> AnalysisResponse:
    created_at = analysis.created_at
    if created_at.tzinfo is None:
        created_at = created_at.replace(tzinfo=UTC)
    return AnalysisResponse(
        analysis_id=analysis.id,
        submitted_url=analysis.display_url,
        classification=analysis.classification,
        threat_type=analysis.threat_type,
        malicious_probability=analysis.malicious_probability,
        confidence=analysis.confidence,
        decision_source=analysis.decision_source,
        reasons=analysis.reasons,
        feed_matches=analysis.feed_matches,
        requires_analyst_review=analysis.requires_analyst_review,
        model_version=analysis.model_version,
        dataset_version=analysis.dataset_version,
        model_backend=analysis.model_backend,
        created_at=created_at,
    )
