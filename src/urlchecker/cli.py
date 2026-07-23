from __future__ import annotations

import argparse
import json

from urlchecker.config import get_settings
from urlchecker.database import SessionLocal, create_tables
from urlchecker.feed_store import FeedStore
from urlchecker.model_service import build_predictor
from urlchecker.services import AnalysisService


def main() -> None:
    parser = argparse.ArgumentParser(description="Analyze a URL without visiting it")
    parser.add_argument("url", help="HTTP or HTTPS URL")
    args = parser.parse_args()

    settings = get_settings()
    create_tables()
    predictor = build_predictor(settings)
    service = AnalysisService(
        settings,
        predictor,
        FeedStore(settings.feed_path, max_url_length=settings.max_url_length),
    )
    with SessionLocal() as session:
        result = service.analyze(args.url, session)
    print(json.dumps(result.model_dump(mode="json"), indent=2))


if __name__ == "__main__":
    main()
