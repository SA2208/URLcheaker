from __future__ import annotations

import hashlib
import hmac
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="strict")).hexdigest()


def redact_url(url: str, *, retain_query_keys: bool = True) -> str:
    parsed = urlsplit(url)
    hostname = parsed.hostname or ""
    if ":" in hostname and not hostname.startswith("["):
        hostname = f"[{hostname}]"
    netloc = hostname
    if parsed.port is not None:
        netloc = f"{netloc}:{parsed.port}"

    query = ""
    if retain_query_keys and parsed.query:
        query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
        query = urlencode([(key, "REDACTED") for key, _ in query_pairs])

    return urlunsplit(
        (parsed.scheme, netloc, parsed.path, query, "")
    )


def verify_model_signature(model_path: Path, key: str) -> bool:
    """Verify an optional HMAC-SHA256 sidecar before loading a serialized model.

    The sidecar path is `<model>.pkl.hmac`. Empty keys intentionally disable verification for
    local development. Production deployments should provide a secret through a secret manager.
    """

    if not key:
        return True

    artifact = model_path.with_suffix(".pkl")
    signature_file = artifact.with_suffix(".pkl.hmac")
    if not artifact.is_file() or not signature_file.is_file():
        return False

    expected = signature_file.read_text(encoding="ascii").strip().lower()
    digest = hmac.new(key.encode("utf-8"), artifact.read_bytes(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, digest)
