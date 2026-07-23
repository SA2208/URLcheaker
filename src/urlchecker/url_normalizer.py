from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from urllib.parse import SplitResult, urlsplit, urlunsplit

import idna

try:
    import tldextract
except ImportError:  # pragma: no cover - exercised only in minimal runtimes
    tldextract = None  # type: ignore[assignment]


class URLValidationError(ValueError):
    """Raised when a submitted URL is unsafe or syntactically unsupported."""


_EXTRACT = (
    tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None) if tldextract is not None else None
)
_ALLOWED_SCHEMES = {"http", "https"}


@dataclass(frozen=True, slots=True)
class NormalizedURL:
    original: str
    normalized: str
    scheme: str
    hostname: str
    port: int | None
    path: str
    query: str
    registrable_domain: str


def _contains_control_characters(value: str) -> bool:
    return any(ord(character) < 32 or ord(character) == 127 for character in value)


def _normalize_hostname(hostname: str) -> str:
    value = hostname.rstrip(".").lower()
    try:
        ipaddress.ip_address(value)
        return value
    except ValueError:
        pass

    try:
        return idna.encode(value, uts46=True, std3_rules=True).decode("ascii").lower()
    except idna.IDNAError as exc:
        raise URLValidationError(
            "Hostname contains invalid internationalized-domain syntax"
        ) from exc


def _registrable_domain(hostname: str) -> str:
    try:
        ipaddress.ip_address(hostname)
        return hostname
    except ValueError:
        if _EXTRACT is not None:
            extracted = _EXTRACT(hostname)
            return extracted.top_domain_under_public_suffix or hostname
        labels = hostname.split(".")
        return ".".join(labels[-2:]) if len(labels) >= 2 else hostname


def normalize_url(raw_url: str, *, max_length: int = 4096) -> NormalizedURL:
    if not isinstance(raw_url, str):
        raise URLValidationError("URL must be a string")

    candidate = raw_url.strip()
    if not candidate:
        raise URLValidationError("URL is required")
    if len(candidate) > max_length:
        raise URLValidationError(f"URL exceeds the {max_length}-character limit")
    if _contains_control_characters(candidate):
        raise URLValidationError("URL contains control characters")

    parsed: SplitResult = urlsplit(candidate)
    scheme = parsed.scheme.lower()
    if scheme not in _ALLOWED_SCHEMES:
        raise URLValidationError("Only HTTP and HTTPS URLs are supported")
    if not parsed.hostname:
        raise URLValidationError("URL must include a hostname")
    if parsed.username is not None or parsed.password is not None:
        raise URLValidationError("Credentials in URLs are not accepted")

    hostname = _normalize_hostname(parsed.hostname)
    try:
        port = parsed.port
    except ValueError as exc:
        raise URLValidationError("URL contains an invalid port") from exc

    if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
        port = None

    display_host = hostname
    try:
        if ipaddress.ip_address(hostname).version == 6:
            display_host = f"[{hostname}]"
    except ValueError:
        pass

    netloc = display_host if port is None else f"{display_host}:{port}"
    path = parsed.path or "/"
    normalized = urlunsplit((scheme, netloc, path, parsed.query, ""))

    return NormalizedURL(
        original=candidate,
        normalized=normalized,
        scheme=scheme,
        hostname=hostname,
        port=port,
        path=path,
        query=parsed.query,
        registrable_domain=_registrable_domain(hostname),
    )
