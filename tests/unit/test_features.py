from __future__ import annotations

from urlchecker.features import extract_features, feature_reasons
from urlchecker.url_normalizer import normalize_url


def test_extracts_high_risk_features() -> None:
    normalized = normalize_url(
        "http://127.0.0.1/login/verify/update.exe?next=http%3A%2F%2Fevil.test"
    )
    features = extract_features(normalized)
    assert features["has_ip_hostname"] == 1
    assert features["has_executable_extension"] == 0  # Query follows the extension.
    assert features["has_nested_url"] == 1
    assert features["suspicious_token_count"] >= 3
    assert any(reason["code"] == "IP_HOSTNAME" for reason in feature_reasons(features))


def test_benign_example_has_no_high_risk_reason() -> None:
    features = extract_features(normalize_url("https://www.example.com/docs/index.html"))
    reason_codes = {reason["code"] for reason in feature_reasons(features)}
    assert "IP_HOSTNAME" not in reason_codes
    assert "NESTED_URL" not in reason_codes
