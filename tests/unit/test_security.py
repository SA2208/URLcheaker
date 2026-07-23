from __future__ import annotations

import hashlib
import hmac
from pathlib import Path

from urlchecker.security import redact_url, verify_model_signature


def test_redacts_query_values_and_credentials() -> None:
    value = redact_url("https://user:secret@example.com/path?token=abc&next=private")
    assert value == "https://example.com/path?token=REDACTED&next=REDACTED"
    assert "secret" not in value
    assert "abc" not in value


def test_model_hmac_verification(tmp_path: Path) -> None:
    base = tmp_path / "model"
    artifact = base.with_suffix(".pkl")
    artifact.write_bytes(b"trusted-model")
    key = "k" * 32
    signature = hmac.new(key.encode(), artifact.read_bytes(), hashlib.sha256).hexdigest()
    artifact.with_suffix(".pkl.hmac").write_text(signature, encoding="ascii")
    assert verify_model_signature(base, key) is True
    artifact.write_bytes(b"tampered")
    assert verify_model_signature(base, key) is False
