from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_prefix="URLCHECKER_",
        case_sensitive=False,
        extra="ignore",
    )

    environment: Literal["development", "test", "production"] = "development"
    database_url: str = "sqlite+pysqlite:///./urlchecker.db"
    model_backend: Literal["heuristic", "pycaret"] = "heuristic"
    model_path: Path = Path("ml/models/urlchecker_pycaret")
    model_version: str = "heuristic-1.0.0"
    dataset_version: str = "demo-synthetic-1"
    feed_path: Path = Path("data/feeds/sample_feed.json")
    malicious_threshold: float = Field(default=0.80, ge=0.5, le=1.0)
    benign_threshold: float = Field(default=0.20, ge=0.0, le=0.5)
    max_url_length: int = Field(default=4096, ge=128, le=32768)
    rate_limit_per_minute: int = Field(default=60, ge=1, le=10000)
    cors_origins: list[str] = ["http://localhost:5173"]
    store_full_urls: bool = False
    auto_create_tables: bool = True
    model_hmac_key: str = ""

    @model_validator(mode="after")
    def validate_threshold_order(self) -> "Settings":
        if self.benign_threshold >= self.malicious_threshold:
            raise ValueError("benign_threshold must be lower than malicious_threshold")
        if self.environment == "production" and self.store_full_urls:
            raise ValueError("STORE_FULL_URLS is disabled by secure production defaults")
        if (
            self.environment == "production"
            and self.model_backend == "pycaret"
            and len(self.model_hmac_key) < 32
        ):
            raise ValueError(
                "Production PyCaret mode requires MODEL_HMAC_KEY with at least 32 characters"
            )
        return self


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
