from __future__ import annotations

import json
import math
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from urlchecker.config import Settings
from urlchecker.security import verify_model_signature


@dataclass(frozen=True, slots=True)
class ModelPrediction:
    malicious_probability: float
    model_version: str
    backend: str


class Predictor(Protocol):
    def predict(self, features: dict[str, float]) -> ModelPrediction: ...


class HeuristicPredictor:
    """Deterministic development fallback.

    This is intentionally not represented as a trained production model. It allows the complete
    service to run before a licensed, versioned dataset has been collected and approved.
    """

    _BIAS = -4.2
    _WEIGHTS = {
        "url_length": 0.004,
        "digit_ratio": 1.8,
        "hyphen_count": 0.08,
        "at_count": 1.5,
        "percent_count": 0.06,
        "subdomain_count": 0.38,
        "query_parameter_count": 0.06,
        "has_https": -0.35,
        "has_explicit_port": 0.35,
        "has_ip_hostname": 2.4,
        "has_punycode": 1.25,
        "has_double_slash_in_path": 0.5,
        "has_executable_extension": 1.8,
        "has_nested_url": 1.7,
        "has_base64_like_token": 1.0,
        "suspicious_token_count": 0.75,
        "longest_token_length": 0.018,
        "url_entropy": 0.12,
    }

    def __init__(self, model_version: str) -> None:
        self.model_version = model_version

    def predict(self, features: dict[str, float]) -> ModelPrediction:
        score = self._BIAS + sum(
            weight * features.get(feature_name, 0.0)
            for feature_name, weight in self._WEIGHTS.items()
        )
        probability = 1.0 / (1.0 + math.exp(-max(-30.0, min(30.0, score))))
        return ModelPrediction(
            malicious_probability=round(probability, 6),
            model_version=self.model_version,
            backend="heuristic",
        )


class PyCaretPredictor:
    def __init__(self, model_path: Path, model_version: str, hmac_key: str) -> None:
        if not verify_model_signature(model_path, hmac_key):
            raise RuntimeError("Model signature verification failed")
        try:
            import pandas as pd
            from pycaret.classification import load_model, predict_model
        except ImportError as exc:
            raise RuntimeError(
                "PyCaret backend requested but the ML runtime dependencies are not installed"
            ) from exc

        self._pd = pd
        self._predict_model = predict_model
        self._model = load_model(str(model_path))
        metadata = self._read_metadata(model_path)
        self.model_version = str(metadata.get("model_version", model_version))
        raw_feature_names = metadata.get("feature_names", [])
        self._feature_names = tuple(str(name) for name in raw_feature_names)

    @staticmethod
    def _read_metadata(model_path: Path) -> dict[str, Any]:
        metadata_path = model_path.with_suffix(".metadata.json")
        if not metadata_path.is_file():
            return {}
        value = json.loads(metadata_path.read_text(encoding="utf-8"))
        if not isinstance(value, dict):
            raise RuntimeError("Model metadata must be a JSON object")
        return value

    def predict(self, features: dict[str, float]) -> ModelPrediction:
        if self._feature_names:
            expected = set(self._feature_names)
            actual = set(features)
            if expected != actual:
                missing = sorted(expected - actual)
                extra = sorted(actual - expected)
                raise RuntimeError(
                    f"Feature schema mismatch; missing={missing}, extra={extra}"
                )
            features = {name: features[name] for name in self._feature_names}
        frame = self._pd.DataFrame([features])
        output = self._predict_model(self._model, data=frame, raw_score=True, verbose=False)
        row: dict[str, Any] = output.iloc[0].to_dict()
        label = row.get("prediction_label")

        probability: float | None = None
        malicious_columns = [
            name
            for name in row
            if str(name).lower() in {"prediction_score_1", "score_1", "prediction_score_malicious"}
        ]
        if malicious_columns:
            probability = float(row[malicious_columns[0]])
        elif "prediction_score" in row:
            predicted_score = float(row["prediction_score"])
            probability = (
                predicted_score
                if str(label).lower() in {"1", "malicious", "true"}
                else 1 - predicted_score
            )

        if probability is None:
            raise RuntimeError("PyCaret prediction output does not expose a malicious-class score")

        return ModelPrediction(
            malicious_probability=round(max(0.0, min(1.0, probability)), 6),
            model_version=self.model_version,
            backend="pycaret",
        )


def build_predictor(settings: Settings) -> Predictor:
    if settings.model_backend == "pycaret":
        return PyCaretPredictor(
            model_path=settings.model_path,
            model_version=settings.model_version,
            hmac_key=settings.model_hmac_key,
        )
    return HeuristicPredictor(settings.model_version)
