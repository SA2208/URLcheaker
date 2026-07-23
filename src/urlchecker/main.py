from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from urlchecker.api import router
from urlchecker.config import get_settings
from urlchecker.database import create_tables
from urlchecker.feed_store import FeedStore
from urlchecker.middleware import (
    InMemoryRateLimitMiddleware,
    RequestIDMiddleware,
    SecurityHeadersMiddleware,
)
from urlchecker.model_service import build_predictor
from urlchecker.services import AnalysisService
from urlchecker.url_normalizer import URLValidationError


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings = get_settings()
    if settings.auto_create_tables:
        create_tables()
    predictor = build_predictor(settings)
    feed_store = FeedStore(settings.feed_path, max_url_length=settings.max_url_length)
    app.state.settings = settings
    app.state.predictor = predictor
    app.state.feed_store = feed_store
    app.state.analysis_service = AnalysisService(settings, predictor, feed_store)
    yield


settings = get_settings()
app = FastAPI(
    title="URLCHEAKER API",
    version="0.1.0",
    description="SOC-oriented lexical URL triage. The service does not visit submitted URLs.",
    lifespan=lifespan,
    docs_url="/docs" if settings.environment != "production" else None,
    redoc_url=None,
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "X-Request-ID"],
)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RequestIDMiddleware)
app.add_middleware(
    InMemoryRateLimitMiddleware,
    requests_per_minute=settings.rate_limit_per_minute,
)
app.include_router(router)


@app.get("/health/live", include_in_schema=False)
def liveness() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/health/ready", include_in_schema=False)
def readiness(request: Request) -> JSONResponse:
    ready = hasattr(request.app.state, "analysis_service")
    return JSONResponse(
        status_code=200 if ready else 503,
        content={"status": "ok" if ready else "degraded"},
    )


@app.exception_handler(URLValidationError)
def handle_url_validation_error(_request: Request, exc: URLValidationError) -> JSONResponse:
    return JSONResponse(status_code=400, content={"detail": str(exc)})


@app.exception_handler(RequestValidationError)
def handle_request_validation_error(
    _request: Request, exc: RequestValidationError
) -> JSONResponse:
    errors = [
        {"field": ".".join(str(part) for part in error["loc"]), "message": error["msg"]}
        for error in exc.errors()
    ]
    return JSONResponse(status_code=422, content={"detail": "Invalid request", "errors": errors})
