from __future__ import annotations

from fastapi.testclient import TestClient

from urlchecker.main import app


def test_analyze_known_feed_url() -> None:
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/analyses",
            json={"url": "http://known-malware.test/dropper.exe"},
        )
    assert response.status_code == 201
    payload = response.json()
    assert payload["classification"] == "malicious"
    assert payload["decision_source"] in {"threat_feed", "combined"}
    assert payload["threat_type"] == "malware"
    assert payload["submitted_url"] == "http://known-malware.test/dropper.exe"


def test_rejects_non_http_scheme() -> None:
    with TestClient(app) as client:
        response = client.post("/api/v1/analyses", json={"url": "javascript:alert(1)"})
    assert response.status_code == 400
    assert response.json()["detail"] == "Only HTTP and HTTPS URLs are supported"


def test_history_and_verdict_flow() -> None:
    with TestClient(app) as client:
        create_response = client.post(
            "/api/v1/analyses",
            json={"url": "https://www.example.com/docs?session=secret"},
        )
        assert create_response.status_code == 201
        analysis_id = create_response.json()["analysis_id"]
        assert "secret" not in create_response.json()["submitted_url"]

        history_response = client.get("/api/v1/analyses?page=1&page_size=10")
        assert history_response.status_code == 200
        assert history_response.json()["total"] >= 1

        summary_response = client.get("/api/v1/dashboard/summary")
        assert summary_response.status_code == 200
        assert summary_response.json()["total"] >= 1

        verdict_response = client.post(
            f"/api/v1/analyses/{analysis_id}/verdicts",
            json={"verdict": "confirmed_benign", "notes": "Approved test domain."},
        )
        assert verdict_response.status_code == 201
        assert verdict_response.json()["analysis_id"] == analysis_id


def test_security_headers_present() -> None:
    with TestClient(app) as client:
        response = client.get("/health/live")
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
