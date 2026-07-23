from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import pandas as pd
from sklearn.metrics import (
    average_precision_score,
    brier_score_loss,
    classification_report,
    confusion_matrix,
    matthews_corrcoef,
    roc_auc_score,
)
from sklearn.model_selection import GroupShuffleSplit, StratifiedGroupKFold

from urlchecker.features import extract_features
from urlchecker.url_normalizer import normalize_url


@dataclass(frozen=True)
class FeatureDataset:
    frame: pd.DataFrame
    groups: pd.Series
    timestamps: pd.Series | None
    sources: pd.Series | None


def build_feature_dataset(dataset_path: Path) -> FeatureDataset:
    source = pd.read_csv(dataset_path)
    required = {"url", "label"}
    if not required.issubset(source.columns):
        raise ValueError(f"Dataset must contain columns: {sorted(required)}")

    feature_rows: list[dict[str, float]] = []
    labels: list[int] = []
    groups: list[str] = []
    for row in source.itertuples(index=False):
        normalized = normalize_url(str(row.url))
        feature_rows.append(extract_features(normalized))
        raw_label = str(row.label).strip().lower()
        labels.append(1 if raw_label in {"malicious", "1", "true"} else 0)
        groups.append(normalized.registrable_domain)

    frame = pd.DataFrame(feature_rows)
    frame["label"] = labels
    timestamps = (
        pd.to_datetime(source["first_seen"], utc=True, errors="raise")
        if "first_seen" in source.columns
        else None
    )
    sources = source["source"].astype(str) if "source" in source.columns else None
    return FeatureDataset(
        frame=frame,
        groups=pd.Series(groups, name="registrable_domain"),
        timestamps=timestamps,
        sources=sources,
    )


def _has_both_classes(frame: pd.DataFrame) -> bool:
    return frame["label"].nunique() == 2 and frame["label"].value_counts().min() >= 2


def split_dataset(
    dataset: FeatureDataset,
    *,
    seed: int,
    holdout_source: str | None,
) -> tuple[pd.DataFrame, pd.DataFrame, pd.Series, str]:
    frame = dataset.frame
    groups = dataset.groups

    if holdout_source is not None:
        if dataset.sources is None:
            raise ValueError("--holdout-source requires a source column")
        test_mask = dataset.sources == holdout_source
        train_mask = ~test_mask
        strategy = f"source_holdout:{holdout_source}"
    elif dataset.timestamps is not None:
        cutoff = dataset.timestamps.quantile(0.80)
        train_mask = dataset.timestamps < cutoff
        test_mask = dataset.timestamps >= cutoff
        strategy = f"temporal:{cutoff.isoformat()}"
    else:
        splitter = GroupShuffleSplit(n_splits=1, test_size=0.20, random_state=seed)
        train_indices, test_indices = next(splitter.split(frame, frame["label"], groups))
        train_mask = frame.index.isin(train_indices)
        test_mask = frame.index.isin(test_indices)
        strategy = "group_shuffle"

    train_groups_set = set(groups[train_mask])
    test_mask = test_mask & ~groups.isin(train_groups_set)

    train = frame[train_mask].reset_index(drop=True)
    test = frame[test_mask].reset_index(drop=True)
    train_groups = groups[train_mask].reset_index(drop=True)
    test_groups = groups[test_mask].reset_index(drop=True)

    insufficient_split = (
        len(train) < 20
        or len(test) < 8
        or not _has_both_classes(train)
        or not _has_both_classes(test)
    )
    if insufficient_split:
        splitter = GroupShuffleSplit(n_splits=1, test_size=0.20, random_state=seed)
        train_indices, test_indices = next(splitter.split(frame, frame["label"], groups))
        train = frame.iloc[train_indices].reset_index(drop=True)
        test = frame.iloc[test_indices].reset_index(drop=True)
        train_groups = groups.iloc[train_indices].reset_index(drop=True)
        test_groups = groups.iloc[test_indices].reset_index(drop=True)
        strategy = "group_shuffle_fallback"

    overlap = set(train_groups).intersection(set(test_groups))
    if overlap:
        raise RuntimeError("Registrable-domain leakage remains after splitting")
    return train, test, train_groups, strategy


def malicious_probability(predictions: pd.DataFrame) -> pd.Series:
    for candidate in ("prediction_score_1", "Score_1"):
        if candidate in predictions.columns:
            return predictions[candidate].astype(float)
    if "prediction_score" in predictions.columns and "prediction_label" in predictions.columns:
        score = predictions["prediction_score"].astype(float)
        label = predictions["prediction_label"].astype(int)
        return score.where(label == 1, 1.0 - score)
    raise RuntimeError("Unable to identify malicious-class probabilities in PyCaret output")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--holdout-source")
    parser.add_argument("--mlflow-uri")
    parser.add_argument("--experiment-name", default="URLCHEAKER")
    args = parser.parse_args()

    try:
        from pycaret.classification import (
            calibrate_model,
            compare_models,
            predict_model,
            save_model,
            setup,
            tune_model,
        )
    except ImportError as exc:
        raise SystemExit(
            "PyCaret is not installed. Use Python 3.11 and install ml/requirements.txt."
        ) from exc

    dataset = build_feature_dataset(args.dataset)
    train, test, train_groups, split_strategy = split_dataset(
        dataset,
        seed=args.seed,
        holdout_source=args.holdout_source,
    )

    groups_per_class = train.assign(group=train_groups).groupby("label")["group"].nunique()
    folds = min(5, int(groups_per_class.min()))
    if folds < 2:
        raise ValueError("Each class needs at least two independent registrable domains")

    setup(
        data=train,
        target="label",
        test_data=test,
        session_id=args.seed,
        fold_strategy=StratifiedGroupKFold(n_splits=folds, shuffle=True, random_state=args.seed),
        fold_groups=train_groups,
        preprocess=False,
        normalize=False,
        remove_multicollinearity=False,
        html=False,
        verbose=False,
        n_jobs=-1,
    )
    candidate = compare_models(sort="AUC", turbo=True)
    tuned = tune_model(candidate, optimize="AUC", choose_better=True)
    calibrated = calibrate_model(tuned, method="sigmoid")

    predictions = predict_model(calibrated, data=test, raw_score=True, verbose=False)
    probability = malicious_probability(predictions)
    predicted = (probability >= 0.5).astype(int)
    actual = test["label"].astype(int)
    matrix = confusion_matrix(actual, predicted, labels=[0, 1])
    true_negative, false_positive, false_negative, true_positive = matrix.ravel()
    false_positive_rate = false_positive / max(1, false_positive + true_negative)
    false_negative_rate = false_negative / max(1, false_negative + true_positive)

    metrics = {
        "roc_auc": roc_auc_score(actual, probability),
        "pr_auc": average_precision_score(actual, probability),
        "brier_score": brier_score_loss(actual, probability),
        "mcc": matthews_corrcoef(actual, predicted),
        "false_positive_rate_at_0_5": false_positive_rate,
        "false_negative_rate_at_0_5": false_negative_rate,
        "confusion_matrix": matrix.tolist(),
        "classification_report": classification_report(
            actual, predicted, output_dict=True, zero_division=0
        ),
    }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    save_model(calibrated, str(args.output))
    feature_names = sorted(column for column in dataset.frame.columns if column != "label")
    feature_schema_hash = hashlib.sha256("\n".join(feature_names).encode()).hexdigest()
    model_version = datetime.now(UTC).strftime("urlchecker-%Y.%m.%d-%H%M%S")
    metadata = {
        "model_version": model_version,
        "created_at": datetime.now(UTC).isoformat(),
        "dataset": str(args.dataset),
        "dataset_sha256": hashlib.sha256(args.dataset.read_bytes()).hexdigest(),
        "feature_schema_sha256": feature_schema_hash,
        "feature_names": feature_names,
        "train_rows": len(train),
        "test_rows": len(test),
        "split_strategy": split_strategy,
        "cross_validation_folds": folds,
        "metrics": metrics,
        "warning": "Promotion still requires independent temporal and source-holdout reports.",
    }
    metadata_path = args.output.with_suffix(".metadata.json")
    metadata_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")

    if args.mlflow_uri:
        try:
            import mlflow
        except ImportError as exc:
            raise SystemExit(
                "MLflow logging requested but ml/requirements-ops.txt is not installed"
            ) from exc
        mlflow.set_tracking_uri(args.mlflow_uri)
        mlflow.set_experiment(args.experiment_name)
        with mlflow.start_run(run_name=model_version):
            mlflow.log_params(
                {
                    "model_version": model_version,
                    "dataset_sha256": metadata["dataset_sha256"],
                    "split_strategy": split_strategy,
                    "cross_validation_folds": folds,
                    "seed": args.seed,
                }
            )
            mlflow.log_metrics(
                {key: float(value) for key, value in metrics.items() if isinstance(value, int | float)}
            )
            mlflow.log_artifact(str(args.output.with_suffix(".pkl")), artifact_path="model")
            mlflow.log_artifact(str(metadata_path), artifact_path="model")

    print(json.dumps(metadata, indent=2))


if __name__ == "__main__":
    main()
