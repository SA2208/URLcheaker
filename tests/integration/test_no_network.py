from __future__ import annotations

import socket

from fastapi.testclient import TestClient

from urlchecker.main import app


def test_analysis_does_not_resolve_or_fetch_submitted_host(
    monkeypatch,  # type: ignore[no-untyped-def]
) -> None:
    def fail_resolution(*_args, **_kwargs):  # type: ignore[no-untyped-def]
        raise AssertionError("Network resolution was attempted")

    monkeypatch.setattr(socket, "getaddrinfo", fail_resolution)
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/analyses",
            json={"url": "https://unresolvable.example.test/account/verify"},
        )
    assert response.status_code == 201
