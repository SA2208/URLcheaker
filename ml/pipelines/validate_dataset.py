from __future__ import annotations

import argparse
import csv
from collections import Counter, defaultdict
from pathlib import Path

from urlchecker.url_normalizer import URLValidationError, normalize_url

REQUIRED_COLUMNS = {"url", "label"}
ALLOWED_LABELS = {"benign", "malicious", "0", "1"}


def validate_dataset(path: Path) -> dict[str, object]:
    rows: list[dict[str, str]] = []
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        missing = REQUIRED_COLUMNS.difference(reader.fieldnames or [])
        if missing:
            raise ValueError(f"Dataset is missing columns: {sorted(missing)}")
        rows = list(reader)

    if len(rows) < 20:
        raise ValueError("Dataset must contain at least 20 rows")

    labels = Counter()
    canonical_labels: dict[str, set[str]] = defaultdict(set)
    domain_labels: dict[str, set[str]] = defaultdict(set)
    invalid_rows: list[int] = []

    for index, row in enumerate(rows, start=2):
        label = row["label"].strip().lower()
        if label not in ALLOWED_LABELS:
            raise ValueError(f"Invalid label at CSV line {index}: {label!r}")
        canonical_label = "malicious" if label in {"malicious", "1"} else "benign"
        labels[canonical_label] += 1
        try:
            normalized = normalize_url(row["url"])
        except URLValidationError:
            invalid_rows.append(index)
            continue
        canonical_labels[normalized.normalized].add(canonical_label)
        domain_labels[normalized.registrable_domain].add(canonical_label)

    conflicts = [url for url, values in canonical_labels.items() if len(values) > 1]
    mixed_domains = [domain for domain, values in domain_labels.items() if len(values) > 1]
    if invalid_rows:
        raise ValueError(f"Invalid URLs at CSV lines: {invalid_rows[:20]}")
    if conflicts:
        raise ValueError(f"Conflicting labels for {len(conflicts)} canonical URLs")
    if min(labels.values(), default=0) < 5:
        raise ValueError("Each class must contain at least five rows")

    return {
        "rows": len(rows),
        "labels": dict(labels),
        "unique_urls": len(canonical_labels),
        "unique_domains": len(domain_labels),
        "mixed_label_domains": len(mixed_domains),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", type=Path, required=True)
    args = parser.parse_args()
    report = validate_dataset(args.dataset)
    for key, value in report.items():
        print(f"{key}: {value}")


if __name__ == "__main__":
    main()
