from __future__ import annotations

import os

os.environ.setdefault("URLCHECKER_ENVIRONMENT", "test")
os.environ.setdefault("URLCHECKER_DATABASE_URL", "sqlite+pysqlite:///:memory:")
os.environ.setdefault("URLCHECKER_RATE_LIMIT_PER_MINUTE", "1000")
os.environ.setdefault("URLCHECKER_MODEL_BACKEND", "heuristic")
os.environ.setdefault("URLCHECKER_FEED_PATH", "data/feeds/sample_feed.json")
