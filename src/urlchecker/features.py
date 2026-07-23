from __future__ import annotations

import ipaddress
import math
import re
from collections import Counter
from urllib.parse import parse_qsl, unquote

from urlchecker.url_normalizer import NormalizedURL

SUSPICIOUS_TOKENS = frozenset(
    {
        "account",
        "auth",
        "bank",
        "confirm",
        "credential",
        "invoice",
        "login",
        "password",
        "payment",
        "recover",
        "secure",
        "signin",
        "support",
        "unlock",
        "update",
        "verify",
        "wallet",
    }
)
_EXECUTABLE_EXTENSIONS = (".exe", ".dll", ".scr", ".js", ".jar", ".msi", ".ps1", ".bat")
_TOKEN_RE = re.compile(r"[a-zA-Z0-9]+")
_BASE64_RE = re.compile(r"(?:[A-Za-z0-9+/]{24,}={0,2})")
_ENCODED_NESTED_URL_RE = re.compile(r"https?(?:://|%3a%2f%2f)", re.IGNORECASE)


def _ratio(part: int, total: int) -> float:
    return part / total if total else 0.0


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    frequencies = Counter(value)
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in frequencies.values())


def _is_ip_address(hostname: str) -> int:
    try:
        ipaddress.ip_address(hostname)
        return 1
    except ValueError:
        return 0


def extract_features(url: NormalizedURL) -> dict[str, float]:
    value = url.normalized
    lower = value.lower()
    hostname = url.hostname.lower()
    decoded_path_query = unquote(f"{url.path}?{url.query}").lower()
    tokens = _TOKEN_RE.findall(lower)
    suspicious_count = sum(token in SUSPICIOUS_TOKENS for token in tokens)
    digits = sum(character.isdigit() for character in value)
    alpha = sum(character.isalpha() for character in value)
    special = len(value) - digits - alpha
    labels = hostname.split(".") if hostname else []
    query_pairs = parse_qsl(url.query, keep_blank_values=True)

    return {
        "url_length": float(len(value)),
        "hostname_length": float(len(hostname)),
        "path_length": float(len(url.path)),
        "query_length": float(len(url.query)),
        "digit_count": float(digits),
        "digit_ratio": _ratio(digits, len(value)),
        "alpha_ratio": _ratio(alpha, len(value)),
        "special_ratio": _ratio(special, len(value)),
        "dot_count": float(value.count(".")),
        "hyphen_count": float(value.count("-")),
        "slash_count": float(value.count("/")),
        "at_count": float(value.count("@")),
        "percent_count": float(value.count("%")),
        "equals_count": float(value.count("=")),
        "ampersand_count": float(value.count("&")),
        "subdomain_count": float(max(0, len(labels) - 2)),
        "max_hostname_label_length": float(max((len(label) for label in labels), default=0)),
        "path_segment_count": float(len([segment for segment in url.path.split("/") if segment])),
        "query_parameter_count": float(len(query_pairs)),
        "has_https": float(url.scheme == "https"),
        "has_explicit_port": float(url.port is not None),
        "has_ip_hostname": float(_is_ip_address(hostname)),
        "has_punycode": float(any(label.startswith("xn--") for label in labels)),
        "has_double_slash_in_path": float("//" in url.path),
        "has_executable_extension": float(decoded_path_query.endswith(_EXECUTABLE_EXTENSIONS)),
        "has_nested_url": float(bool(_ENCODED_NESTED_URL_RE.search(url.query))),
        "has_base64_like_token": float(bool(_BASE64_RE.search(url.path + url.query))),
        "suspicious_token_count": float(suspicious_count),
        "longest_token_length": float(max((len(token) for token in tokens), default=0)),
        "url_entropy": _entropy(value),
        "hostname_entropy": _entropy(hostname),
    }


def feature_reasons(features: dict[str, float]) -> list[dict[str, str | float]]:
    rules: list[tuple[bool, str, str, str]] = [
        (
            features["has_ip_hostname"] == 1,
            "IP_HOSTNAME",
            "The URL uses an IP address instead of a domain name.",
            "has_ip_hostname",
        ),
        (
            features["has_punycode"] == 1,
            "PUNYCODE_HOSTNAME",
            "The hostname contains internationalized-domain encoding.",
            "has_punycode",
        ),
        (
            features["suspicious_token_count"] >= 2,
            "SUSPICIOUS_TOKENS",
            "The URL contains multiple account, authentication, or payment-related tokens.",
            "suspicious_token_count",
        ),
        (
            features["subdomain_count"] >= 3,
            "EXCESSIVE_SUBDOMAINS",
            "The hostname contains an unusually deep subdomain hierarchy.",
            "subdomain_count",
        ),
        (
            features["has_nested_url"] == 1,
            "NESTED_URL",
            "The query string contains another URL or encoded redirect target.",
            "has_nested_url",
        ),
        (
            features["has_executable_extension"] == 1,
            "EXECUTABLE_EXTENSION",
            "The URL path appears to reference executable or script content.",
            "has_executable_extension",
        ),
        (
            features["url_length"] >= 180,
            "LONG_URL",
            "The URL is substantially longer than typical interactive URLs.",
            "url_length",
        ),
        (
            features["digit_ratio"] >= 0.30,
            "HIGH_DIGIT_RATIO",
            "A high proportion of the URL consists of digits.",
            "digit_ratio",
        ),
        (
            features["url_entropy"] >= 5.0,
            "HIGH_ENTROPY",
            "The URL has high character entropy consistent with generated tokens.",
            "url_entropy",
        ),
    ]

    return [
        {
            "code": code,
            "description": description,
            "feature_name": feature_name,
            "feature_value": round(features[feature_name], 6),
        }
        for condition, code, description, feature_name in rules
        if condition
    ][:8]
