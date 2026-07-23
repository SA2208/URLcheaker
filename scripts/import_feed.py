from __future__ import annotations

import argparse
import csv
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from urlchecker.url_normalizer import URLValidationError, normalize_url


def load_records(path: Path, url_column: str) -> list[dict[str, Any]]:
    suffix = path.suffix.lower()
    if suffix == ".json":
        value = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(value, list):
            raise ValueError("JSON feed must contain a list of objects")
        return [record for record in value if isinstance(record, dict)]
    if suffix in {".jsonl", ".ndjson"}:
        records = []
        for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if not line.strip():
                continue
            value = json.loads(line)
            if not isinstance(value, dict):
                raise ValueError(f"JSONL line {line_number} is not an object")
            records.append(value)
        return records
    if suffix == ".csv":
        with path.open(newline="", encoding="utf-8-sig") as handle:
            reader = csv.DictReader(handle)
            if url_column not in (reader.fieldnames or []):
                raise ValueError(f"CSV does not contain URL column {url_column!r}")
            return list(reader)
    raise ValueError("Supported input formats are CSV, JSON, and JSONL")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Normalize a locally obtained provider snapshot into the URLCHEAKER feed schema"
    )
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--source", required=True)
    parser.add_argument("--threat-type", required=True)
    parser.add_argument("--url-column", default="url")
    parser.add_argument("--id-column")
    parser.add_argument("--first-seen-column")
    parser.add_argument("--last-seen-column")
    parser.add_argument("--max-url-length", type=int, default=4096)
    args = parser.parse_args()

    if not args.input.is_file():
        raise SystemExit(f"Input snapshot not found: {args.input}")
    raw_sha256 = hashlib.sha256(args.input.read_bytes()).hexdigest()
    imported_at = datetime.now(UTC).isoformat()
    output_records: dict[str, dict[str, Any]] = {}
    invalid = 0
    duplicates = 0

    for position, record in enumerate(load_records(args.input, args.url_column), start=1):
        raw_url = record.get(args.url_column)
        if raw_url is None:
            invalid += 1
            continue
        try:
            normalized = normalize_url(str(raw_url), max_length=args.max_url_length).normalized
        except URLValidationError:
            invalid += 1
            continue
        if normalized in output_records:
            duplicates += 1
            continue
        record_id = (
            str(record.get(args.id_column))
            if args.id_column and record.get(args.id_column) is not None
            else hashlib.sha256(f"{args.source}\0{normalized}".encode()).hexdigest()[:24]
        )
        output_records[normalized] = {
            "url": normalized,
            "source": args.source,
            "source_record_id": record_id,
            "threat_type": args.threat_type,
            "first_seen": record.get(args.first_seen_column) if args.first_seen_column else None,
            "last_seen": record.get(args.last_seen_column) if args.last_seen_column else None,
            "imported_at": imported_at,
            "source_snapshot_sha256": raw_sha256,
            "source_row": position,
        }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    payload = sorted(output_records.values(), key=lambda item: str(item["url"]))
    temporary = args.output.with_suffix(args.output.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    temporary.replace(args.output)
    output_sha256 = hashlib.sha256(args.output.read_bytes()).hexdigest()
    args.output.with_suffix(args.output.suffix + ".sha256").write_text(
        f"{output_sha256}  {args.output.name}\n", encoding="ascii"
    )
    manifest = {
        "source": args.source,
        "threat_type": args.threat_type,
        "input": str(args.input),
        "input_sha256": raw_sha256,
        "output": str(args.output),
        "output_sha256": output_sha256,
        "valid_records": len(payload),
        "invalid_records": invalid,
        "duplicate_records": duplicates,
        "imported_at": imported_at,
    }
    args.output.with_suffix(args.output.suffix + ".manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
