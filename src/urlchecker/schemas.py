from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class AnalyzeURLRequest(BaseModel):
    url: str = Field(min_length=1, max_length=32768)


class ReasonResponse(BaseModel):
    code: str
    description: str
    feature_name: str
    feature_value: float


class FeedMatchResponse(BaseModel):
    source_name: str
    source_record_id: str
    threat_type: str
    first_seen: str | None = None
    last_seen: str | None = None


class AnalysisResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    analysis_id: str
    submitted_url: str
    classification: Literal["malicious", "benign", "uncertain"]
    threat_type: str | None
    malicious_probability: float = Field(ge=0.0, le=1.0)
    confidence: Literal["high", "medium", "low"]
    decision_source: Literal["threat_feed", "machine_learning", "combined"]
    reasons: list[ReasonResponse]
    feed_matches: list[FeedMatchResponse]
    requires_analyst_review: bool
    model_version: str
    dataset_version: str
    model_backend: str
    created_at: datetime


class AnalysisListResponse(BaseModel):
    items: list[AnalysisResponse]
    page: int
    page_size: int
    total: int


class VerdictRequest(BaseModel):
    verdict: Literal[
        "confirmed_malicious",
        "confirmed_benign",
        "needs_more_analysis",
        "false_positive",
        "false_negative",
    ]
    threat_type: str | None = Field(default=None, max_length=64)
    notes: str | None = Field(default=None, max_length=2000)


class VerdictResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    analysis_id: str
    verdict: str
    threat_type: str | None
    notes: str | None
    created_at: datetime


class HealthResponse(BaseModel):
    status: Literal["ok", "degraded"]
    model_backend: str
    model_version: str
    dataset_version: str
    feed_records: int


class DashboardSummaryResponse(BaseModel):
    total: int
    malicious: int
    benign: int
    uncertain: int
    requires_review: int
    threat_feed_decisions: int
