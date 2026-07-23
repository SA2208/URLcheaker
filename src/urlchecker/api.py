from __future__ import annotations

from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.orm import Session

from urlchecker.database import get_db
from urlchecker.db_models import AnalystVerdict
from urlchecker.repository import AnalysisRepository
from urlchecker.schemas import (
    AnalysisListResponse,
    AnalysisResponse,
    AnalyzeURLRequest,
    DashboardSummaryResponse,
    HealthResponse,
    VerdictRequest,
    VerdictResponse,
)
from urlchecker.services import AnalysisService, analysis_to_response

router = APIRouter(prefix="/api/v1")
DbSession = Annotated[Session, Depends(get_db)]


def get_analysis_service(request: Request) -> AnalysisService:
    return request.app.state.analysis_service


@router.post(
    "/analyses",
    response_model=AnalysisResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_analysis(
    payload: AnalyzeURLRequest,
    session: DbSession,
    service: Annotated[AnalysisService, Depends(get_analysis_service)],
) -> AnalysisResponse:
    return service.analyze(payload.url, session)


@router.get("/analyses/{analysis_id}", response_model=AnalysisResponse)
def get_analysis(analysis_id: str, session: DbSession) -> AnalysisResponse:
    analysis = AnalysisRepository(session).get(analysis_id)
    if analysis is None:
        raise HTTPException(status_code=404, detail="Analysis not found")
    return analysis_to_response(analysis)


@router.get("/analyses", response_model=AnalysisListResponse)
def list_analyses(
    session: DbSession,
    page: Annotated[int, Query(ge=1)] = 1,
    page_size: Annotated[int, Query(ge=1, le=100)] = 25,
    classification: Literal["malicious", "benign", "uncertain"] | None = None,
    domain: Annotated[str | None, Query(max_length=253)] = None,
) -> AnalysisListResponse:
    items, total = AnalysisRepository(session).list(
        page=page,
        page_size=page_size,
        classification=classification,
        domain=domain,
    )
    return AnalysisListResponse(
        items=[analysis_to_response(item) for item in items],
        page=page,
        page_size=page_size,
        total=total,
    )


@router.post(
    "/analyses/{analysis_id}/verdicts",
    response_model=VerdictResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_verdict(
    analysis_id: str,
    payload: VerdictRequest,
    session: DbSession,
) -> AnalystVerdict:
    repository = AnalysisRepository(session)
    if repository.get(analysis_id) is None:
        raise HTTPException(status_code=404, detail="Analysis not found")
    verdict = AnalystVerdict(
        analysis_id=analysis_id,
        verdict=payload.verdict,
        threat_type=payload.threat_type,
        notes=payload.notes,
    )
    return repository.add_verdict(verdict)


@router.get("/dashboard/summary", response_model=DashboardSummaryResponse)
def dashboard_summary(session: DbSession) -> DashboardSummaryResponse:
    return DashboardSummaryResponse(**AnalysisRepository(session).summary())


@router.get("/system/health", response_model=HealthResponse)
def system_health(request: Request) -> HealthResponse:
    settings = request.app.state.settings
    predictor = request.app.state.predictor
    feed_store = request.app.state.feed_store
    return HealthResponse(
        status="ok",
        model_backend=settings.model_backend,
        model_version=predictor.model_version,
        dataset_version=settings.dataset_version,
        feed_records=feed_store.record_count,
    )
