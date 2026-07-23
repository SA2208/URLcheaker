from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.sql.elements import ColumnElement
from sqlalchemy.orm import Session

from urlchecker.db_models import Analysis, AnalystVerdict


class AnalysisRepository:
    def __init__(self, session: Session) -> None:
        self.session = session

    def add(self, analysis: Analysis) -> Analysis:
        self.session.add(analysis)
        self.session.commit()
        self.session.refresh(analysis)
        return analysis

    def get(self, analysis_id: str) -> Analysis | None:
        return self.session.get(Analysis, analysis_id)

    def list(
        self,
        *,
        page: int,
        page_size: int,
        classification: str | None = None,
        domain: str | None = None,
    ) -> tuple[list[Analysis], int]:
        filters = []
        if classification:
            filters.append(Analysis.classification == classification)
        if domain:
            filters.append(Analysis.registrable_domain.ilike(f"%{domain}%"))

        statement = select(Analysis).where(*filters)
        count_statement = select(func.count()).select_from(Analysis).where(*filters)
        total = int(self.session.scalar(count_statement) or 0)
        items = list(
            self.session.scalars(
                statement.order_by(Analysis.created_at.desc())
                .offset((page - 1) * page_size)
                .limit(page_size)
            )
        )
        return items, total

    def summary(self) -> dict[str, int]:
        total = int(self.session.scalar(select(func.count()).select_from(Analysis)) or 0)

        def count_where(*conditions: ColumnElement[bool]) -> int:
            statement = select(func.count()).select_from(Analysis).where(*conditions)
            return int(self.session.scalar(statement) or 0)

        return {
            "total": total,
            "malicious": count_where(Analysis.classification == "malicious"),
            "benign": count_where(Analysis.classification == "benign"),
            "uncertain": count_where(Analysis.classification == "uncertain"),
            "requires_review": count_where(Analysis.requires_analyst_review.is_(True)),
            "threat_feed_decisions": count_where(
                Analysis.decision_source.in_(["threat_feed", "combined"])
            ),
        }

    def add_verdict(self, verdict: AnalystVerdict) -> AnalystVerdict:
        self.session.add(verdict)
        self.session.commit()
        self.session.refresh(verdict)
        return verdict
