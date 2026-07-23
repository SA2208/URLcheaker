from __future__ import annotations

import time
from collections import defaultdict, deque
from threading import Lock
from uuid import uuid4

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import Response
from starlette.types import ASGIApp


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["Cache-Control"] = "no-store"
        return response


class RequestIDMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        request_id = request.headers.get("X-Request-ID", str(uuid4()))[:128]
        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        return response


class InMemoryRateLimitMiddleware(BaseHTTPMiddleware):
    """Single-process development limiter.

    Replace with a shared Redis or gateway limiter when multiple API replicas are deployed.
    """

    def __init__(self, app: ASGIApp, requests_per_minute: int) -> None:
        super().__init__(app)
        self.requests_per_minute = requests_per_minute
        self._requests: dict[str, deque[float]] = defaultdict(deque)
        self._lock = Lock()

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        if request.url.path.startswith("/health"):
            return await call_next(request)

        client = request.client.host if request.client else "unknown"
        now = time.monotonic()
        cutoff = now - 60.0
        with self._lock:
            history = self._requests[client]
            while history and history[0] < cutoff:
                history.popleft()
            if len(history) >= self.requests_per_minute:
                return JSONResponse(
                    status_code=429,
                    content={"detail": "Rate limit exceeded"},
                    headers={"Retry-After": "60"},
                )
            history.append(now)
        return await call_next(request)
