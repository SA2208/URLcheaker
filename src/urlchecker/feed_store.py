from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from urlchecker.security import sha256_text
from urlchecker.url_normalizer import URLValidationError, normalize_url


@dataclass(frozen=True, slots=True)
class FeedMatch:
    source_name: str
    source_record_id: str
    threat_type: str
    first_seen: str | None = None
    last_seen: str | None = None


class FeedStore:
    def __init__(self, path: Path, *, max_url_length: int) -> None:
        self._matches: dict[str, list[FeedMatch]] = {}
        self._path = path
        self._max_url_length = max_url_length
        self.reload()

    @property
    def record_count(self) -> int:
        return sum(len(records) for records in self._matches.values())

    def reload(self) -> None:
        self._matches = {}
        if not self._path.is_file():
            return

        raw_records: list[dict[str, Any]] = json.loads(self._path.read_text(encoding="utf-8"))
        for record in raw_records:
            try:
                normalized = normalize_url(
                    str(record["url"]), max_length=self._max_url_length
                ).normalized
            except (KeyError, URLValidationError):
                continue
            key = sha256_text(normalized)
            self._matches.setdefault(key, []).append(
                FeedMatch(
                    source_name=str(record.get("source", "unknown")),
                    source_record_id=str(record.get("source_record_id", key[:16])),
                    threat_type=str(record.get("threat_type", "malicious")),
                    first_seen=_optional_string(record.get("first_seen")),
                    last_seen=_optional_string(record.get("last_seen")),
                )
            )

    def lookup(self, normalized_url: str) -> list[FeedMatch]:
        return list(self._matches.get(sha256_text(normalized_url), []))


def _optional_string(value: Any) -> str | None:
    return None if value is None else str(value)
