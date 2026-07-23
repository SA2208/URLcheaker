from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from urlchecker.database import Base


def _uuid() -> str:
    return str(uuid4())


def _utcnow() -> datetime:
    return datetime.now(UTC)


class Analysis(Base):
    __tablename__ = "analyses"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    display_url: Mapped[str] = mapped_column(Text, nullable=False)
    normalized_url_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    registrable_domain: Mapped[str] = mapped_column(String(253), nullable=False, index=True)
    classification: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    threat_type: Mapped[str | None] = mapped_column(String(64), nullable=True)
    malicious_probability: Mapped[float] = mapped_column(Float, nullable=False)
    confidence: Mapped[str] = mapped_column(String(16), nullable=False)
    decision_source: Mapped[str] = mapped_column(String(32), nullable=False)
    requires_analyst_review: Mapped[bool] = mapped_column(
        Boolean, nullable=False
    )
    reasons: Mapped[list[dict[str, object]]] = mapped_column(JSON, default=list, nullable=False)
    feed_matches: Mapped[list[dict[str, object]]] = mapped_column(
        JSON, default=list, nullable=False
    )
    model_version: Mapped[str] = mapped_column(String(128), nullable=False)
    dataset_version: Mapped[str] = mapped_column(String(128), nullable=False)
    model_backend: Mapped[str] = mapped_column(String(32), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False, index=True
    )

    verdicts: Mapped[list[AnalystVerdict]] = relationship(
        back_populates="analysis", cascade="all, delete-orphan"
    )


class AnalystVerdict(Base):
    __tablename__ = "analyst_verdicts"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    analysis_id: Mapped[str] = mapped_column(
        ForeignKey("analyses.id", ondelete="CASCADE"), nullable=False, index=True
    )
    verdict: Mapped[str] = mapped_column(String(32), nullable=False)
    threat_type: Mapped[str | None] = mapped_column(String(64), nullable=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )

    analysis: Mapped[Analysis] = relationship(back_populates="verdicts")
