from __future__ import annotations

import pytest

from urlchecker.url_normalizer import URLValidationError, normalize_url


def test_normalizes_case_default_port_and_fragment() -> None:
    result = normalize_url(" HTTPS://EXAMPLE.COM:443/path?q=1#fragment ")
    assert result.normalized == "https://example.com/path?q=1"
    assert result.registrable_domain == "example.com"


def test_converts_unicode_hostname_to_idna() -> None:
    result = normalize_url("https://bücher.example/path")
    assert result.hostname == "xn--bcher-kva.example"


@pytest.mark.parametrize(
    "value",
    [
        "javascript:alert(1)",
        "file:///etc/passwd",
        "data:text/plain,test",
        "https://user:password@example.com/",
        "https://exa\x00mple.com/",
        "https://",
        "not-a-url",
    ],
)
def test_rejects_unsupported_or_malformed_urls(value: str) -> None:
    with pytest.raises(URLValidationError):
        normalize_url(value)


def test_accepts_ipv6() -> None:
    result = normalize_url("http://[::1]:8080/test")
    assert result.normalized == "http://[::1]:8080/test"
    assert result.registrable_domain == "::1"
