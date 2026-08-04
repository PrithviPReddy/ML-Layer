"""
Module: Enigma-ML-Layer/train_level3.py

Leakage-free training and evaluation on the official UNSW-NB15 partition.

Replaces train.py, which was a faithful port of the notebook and therefore
carried all four leakage paths deliberately. Nothing produced by train.py should
reach the paper.

Partition roles, from paper/EVIDENCE.md appendix L1.3. The distributed filenames
are inverted, so roles are assigned by row count and never by filename:

    UNSW_NB15_testing-set.csv    175341 rows, the train and validation pool
    UNSW_NB15_training-set.csv    82332 rows, the test set

The test set is transformed and scored exactly once, at the end of a run. It
never informs feature selection, hyperparameter choice or early stopping.
"""

from __future__ import annotations

import argparse
import json
import random
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_recall_fscore_support,
)
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder

from level3_pipeline import (
    NORMAL_CLASS,
    TARGET_COLUMN,
    balance_by_downsampling,
    build_classifier,
    build_resampling_pipeline,
    false_positive_rate,
    feature_selection_scores,
    per_class_false_positive_rates,
    resolve_numeric_columns,
    resolve_sampling_strategy,
    selected_feature_names,
    transform_without_resampling,
)

POOL_FILENAME = "UNSW_NB15_testing-set.csv"
TEST_FILENAME = "UNSW_NB15_training-set.csv"
EXPECTED_POOL_ROWS = 175341
EXPECTED_TEST_ROWS = 82332

DEFAULT_HYPERPARAMETERS = {
    "hidden_units": [64, 32],
    "dropout_rate": 0.2,
    "learning_rate": 1e-3,
    "batch_size": 256,
    "max_epochs": 200,
    "early_stopping_patience": 10,
}


def set_global_seed(seed: int) -> None:
    """Seed Python, NumPy and TensorFlow."""
    random.seed(seed)
    np.random.seed(seed)
    import tensorflow as tf

    tf.random.set_seed(seed)
    tf.keras.utils.set_random_seed(seed)


def load_partitions(data_dir: Path) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Load the official partition, assigning roles by row count.

    Args:
        data_dir: Directory holding the UNSW-NB15 files.

    Returns:
        The train and validation pool, then the test partition.

    Raises:
        ValueError: If the row counts do not match the published partition, which
            would mean the files are not the official split.
    """
    pool = pd.read_csv(data_dir / POOL_FILENAME, low_memory=False)
    test = pd.read_csv(data_dir / TEST_FILENAME, low_memory=False)

    if len(pool) != EXPECTED_POOL_ROWS or len(test) != EXPECTED_TEST_ROWS:
        raise ValueError(
            f"unexpected partition sizes: pool={len(pool)} test={len(test)}, "
            f"expected {EXPECTED_POOL_ROWS} and {EXPECTED_TEST_ROWS}"
        )
    return pool, test


def class_distribution(frame: pd.DataFrame) -> dict[str, int]:
    """Return the class counts of a frame as a plain dict."""
    return {
        str(name): int(count)
        for name, count in frame[TARGET_COLUMN].value_counts().sort_index().items()
    }


def evaluate_predictions(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    probabilities: np.ndarray,
    class_names: list[str],
    normal_index: Optional[int],
) -> dict:
    """Compute the full metric suite for one prediction set.

    Args:
        y_true: True class indices.
        y_pred: Predicted class indices.
        probabilities: Predicted class probability matrix.
        class_names: Class names ordered by index.
        normal_index: Index of the normal class within class_names.

    Returns:
        Every metric the done check requires, JSON serialisable.
    """
    labels = list(range(len(class_names)))
    precision, recall, f1, support = precision_recall_fscore_support(
        y_true, y_pred, labels=labels, zero_division=0
    )
    matrix = confusion_matrix(y_true, y_pred, labels=labels)
    row_totals = matrix.sum(axis=1, keepdims=True)
    normalised = np.divide(
        matrix, row_totals, out=np.zeros_like(matrix, dtype=float), where=row_totals != 0
    )

    return {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "macro_f1": float(f1_score(y_true, y_pred, average="macro", zero_division=0)),
        "weighted_f1": float(f1_score(y_true, y_pred, average="weighted", zero_division=0)),
        "false_positive_rate_normal_as_attack": false_positive_rate(
            y_true, y_pred, normal_index
        ),
        "per_class": {
            class_names[index]: {
                "precision": float(precision[index]),
                "recall": float(recall[index]),
                "f1": float(f1[index]),
                "support": int(support[index]),
                "false_positive_rate": rate,
            }
            for index, rate in enumerate(
                per_class_false_positive_rates(y_true, y_pred, len(class_names))
            )
        },
        "confusion_matrix": matrix.tolist(),
        "confusion_matrix_normalised": normalised.tolist(),
        "classification_report": classification_report(
            y_true, y_pred, labels=labels, target_names=class_names, zero_division=0
        ),
        "mean_predicted_confidence": float(np.max(probabilities, axis=1).mean()),
        "sample_count": int(len(y_true)),
    }


def analyse_holdout(
    probabilities: np.ndarray,
    predictions: np.ndarray,
    class_names: list[str],
    holdout_mask: np.ndarray,
) -> dict:
    """Describe how the model behaves on a class it never saw in training.

    Args:
        probabilities: Predicted class probability matrix over the test set.
        predictions: Predicted class indices over the test set.
        class_names: Class names the model can emit.
        holdout_mask: Boolean mask selecting the held-out class's rows.

    Returns:
        Predicted label distribution and confidence statistics for the held-out
        rows compared against the known rows. Consumed by Level 4.
    """
    holdout_confidence = np.max(probabilities[holdout_mask], axis=1)
    known_confidence = np.max(probabilities[~holdout_mask], axis=1)

    predicted_counts = {}
    for index in predictions[holdout_mask]:
        name = class_names[index]
        predicted_counts[name] = predicted_counts.get(name, 0) + 1

    total = int(holdout_mask.sum())
    return {
        "holdout_sample_count": total,
        "predicted_label_distribution": dict(
            sorted(predicted_counts.items(), key=lambda item: -item[1])
        ),
        "predicted_label_share": {
            name: round(count / total, 4) for name, count in predicted_counts.items()
        }
        if total
        else {},
        "confidence_on_holdout": {
            "mean": float(holdout_confidence.mean()) if total else None,
            "median": float(np.median(holdout_confidence)) if total else None,
            "std": float(holdout_confidence.std()) if total else None,
            "min": float(holdout_confidence.min()) if total else None,
            "max": float(holdout_confidence.max()) if total else None,
        },
        "confidence_on_known": {
            "mean": float(known_confidence.mean()),
            "median": float(np.median(known_confidence)),
            "std": float(known_confidence.std()),
        },
        "confidence_gap_known_minus_holdout": (
            float(known_confidence.mean() - holdout_confidence.mean()) if total else None
        ),
    }


def run(args: argparse.Namespace) -> dict:
    """Execute one full training and evaluation run.

    Args:
        args: Parsed command line arguments.

    Returns:
        The run report, already written to disk.
    """
    import keras
    from tensorflow.keras.utils import to_categorical

    set_global_seed(args.seed)
    started = datetime.now(timezone.utc)

    pool, test = load_partitions(args.data_dir)
    numeric_columns = resolve_numeric_columns(pool)

    train_frame, validation_frame = train_test_split(
        pool,
        test_size=args.validation_size,
        random_state=args.seed,
        stratify=pool[TARGET_COLUMN],
    )

    config_name = "closedset" if args.holdout_class is None else "openset"
    holdout_class = args.holdout_class

    if holdout_class is not None:
        if holdout_class not in set(pool[TARGET_COLUMN]):
            raise ValueError(f"holdout class not present in the pool: {holdout_class}")
        train_frame = train_frame[train_frame[TARGET_COLUMN] != holdout_class]
        validation_frame = validation_frame[validation_frame[TARGET_COLUMN] != holdout_class]

    label_encoder = LabelEncoder()
    label_encoder.fit(sorted(train_frame[TARGET_COLUMN].unique()))
    class_names = [str(name) for name in label_encoder.classes_]
    normal_index = class_names.index(NORMAL_CLASS) if NORMAL_CLASS in class_names else None

    y_train = label_encoder.transform(train_frame[TARGET_COLUMN])
    y_validation = label_encoder.transform(validation_frame[TARGET_COLUMN])

    training_class_counts = {
        int(label): int(count) for label, count in zip(*np.unique(y_train, return_counts=True))
    }
    sampling_strategy = resolve_sampling_strategy(args.smote_strategy, training_class_counts)

    pipeline = build_resampling_pipeline(
        numeric_columns=numeric_columns,
        n_features=args.n_features,
        seed=args.seed,
        sampling_strategy=sampling_strategy,
    )

    x_train_resampled, y_train_resampled = pipeline.fit_resample(train_frame, y_train)
    x_validation = transform_without_resampling(pipeline, validation_frame)

    selected = selected_feature_names(pipeline, numeric_columns)
    selection_scores = feature_selection_scores(pipeline, numeric_columns)

    hyperparameters = dict(DEFAULT_HYPERPARAMETERS)
    model = build_classifier(
        input_dim=x_train_resampled.shape[1],
        num_classes=len(class_names),
        seed=args.seed,
        hyperparameters=hyperparameters,
    )

    history = model.fit(
        x_train_resampled,
        to_categorical(y_train_resampled, num_classes=len(class_names)),
        validation_data=(
            x_validation,
            to_categorical(y_validation, num_classes=len(class_names)),
        ),
        epochs=hyperparameters["max_epochs"],
        batch_size=hyperparameters["batch_size"],
        callbacks=[
            keras.callbacks.EarlyStopping(
                monitor="val_loss",
                patience=hyperparameters["early_stopping_patience"],
                restore_best_weights=True,
            )
        ],
        verbose=2 if args.verbose else 0,
    )

    probabilities_validation = model.predict(x_validation, verbose=0)
    validation_metrics = evaluate_predictions(
        y_validation,
        np.argmax(probabilities_validation, axis=1),
        probabilities_validation,
        class_names,
        normal_index,
    )

    test_natural = test
    test_known = test_natural[test_natural[TARGET_COLUMN].isin(class_names)]
    x_test_natural = transform_without_resampling(pipeline, test_natural)
    probabilities_natural = model.predict(x_test_natural, verbose=0)
    predictions_natural = np.argmax(probabilities_natural, axis=1)

    known_mask = test_natural[TARGET_COLUMN].isin(class_names).to_numpy()
    y_test_known = label_encoder.transform(test_natural.loc[known_mask, TARGET_COLUMN])

    natural_metrics = evaluate_predictions(
        y_test_known,
        predictions_natural[known_mask],
        probabilities_natural[known_mask],
        class_names,
        normal_index,
    )

    balanced_frame = balance_by_downsampling(test_known, TARGET_COLUMN, args.seed)
    x_test_balanced = transform_without_resampling(pipeline, balanced_frame)
    probabilities_balanced = model.predict(x_test_balanced, verbose=0)
    predictions_balanced = np.argmax(probabilities_balanced, axis=1)
    balanced_metrics = evaluate_predictions(
        label_encoder.transform(balanced_frame[TARGET_COLUMN]),
        predictions_balanced,
        probabilities_balanced,
        class_names,
        normal_index,
    )

    holdout_analysis = None
    if holdout_class is not None:
        holdout_mask = (test_natural[TARGET_COLUMN] == holdout_class).to_numpy()
        holdout_analysis = analyse_holdout(
            probabilities_natural, predictions_natural, class_names, holdout_mask
        )
        holdout_analysis["holdout_class"] = holdout_class

    finished = datetime.now(timezone.utc)
    report = {
        "seed": args.seed,
        "config": config_name,
        "holdout_class": holdout_class,
        "started_at_utc": started.isoformat().replace("+00:00", "Z"),
        "finished_at_utc": finished.isoformat().replace("+00:00", "Z"),
        "duration_seconds": round((finished - started).total_seconds(), 2),
        "partition": {
            "pool_file": POOL_FILENAME,
            "pool_rows": int(len(pool)),
            "test_file": TEST_FILENAME,
            "test_rows": int(len(test)),
            "roles_assigned_by": "row count, never filename",
        },
        "split": {
            "train_rows": int(len(train_frame)),
            "validation_rows": int(len(validation_frame)),
            "test_rows": int(len(test)),
            "validation_size": args.validation_size,
            "train_distribution": class_distribution(train_frame),
            "validation_distribution": class_distribution(validation_frame),
            "test_distribution": class_distribution(test),
            "train_rows_after_smote": int(len(x_train_resampled)),
        },
        "classes": {
            "training_classes": class_names,
            "class_index": {str(index): name for index, name in enumerate(class_names)},
            "normal_index": normal_index,
            "holdout_absent_from_training": holdout_class is not None,
        },
        "features": {
            "candidate_numeric_columns": numeric_columns,
            "requested_feature_count": args.n_features,
            "selected_features": selected,
            "selected_feature_count": len(selected),
            "top_scores": selection_scores[: args.n_features],
        },
        "hyperparameters": {**hyperparameters, "smote_strategy": args.smote_strategy},
        "training": {
            "epochs_run": len(history.history["loss"]),
            "best_val_loss": float(min(history.history["val_loss"])),
            "history": {
                key: [float(value) for value in values]
                for key, values in history.history.items()
            },
        },
        "metrics_validation": validation_metrics,
        "metrics_natural": natural_metrics,
        "metrics_balanced": balanced_metrics,
        "holdout_analysis": holdout_analysis,
    }

    write_outputs(args, report, model, pipeline, label_encoder, config_name, natural_metrics)
    return report


def write_outputs(
    args: argparse.Namespace,
    report: dict,
    model,
    pipeline,
    label_encoder,
    config_name: str,
    natural_metrics: dict,
) -> None:
    """Persist metrics, confusion matrix, model, pipeline and class index."""
    import joblib

    results_dir = args.results_dir / "classifier"
    results_dir.mkdir(parents=True, exist_ok=True)
    args.artifacts_dir.mkdir(parents=True, exist_ok=True)

    metrics_path = results_dir / f"metrics_{config_name}_seed{args.seed}.json"
    metrics_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    confusion_path = results_dir / f"confusion_{config_name}_seed{args.seed}.npy"
    np.save(confusion_path, np.array(natural_metrics["confusion_matrix"]))

    if report["holdout_analysis"] is not None:
        holdout_path = results_dir / f"openset_holdout_analysis_seed{args.seed}.json"
        holdout_path.write_text(
            json.dumps(report["holdout_analysis"], indent=2), encoding="utf-8"
        )

    model.save(args.artifacts_dir / f"model_{config_name}_seed{args.seed}.keras")
    joblib.dump(
        {"pipeline": pipeline, "label_encoder": label_encoder},
        args.artifacts_dir / f"pipeline_{config_name}_seed{args.seed}.pkl",
    )
    (args.artifacts_dir / f"class_index_{config_name}.json").write_text(
        json.dumps(report["classes"]["class_index"], indent=2), encoding="utf-8"
    )
    (args.artifacts_dir / "hyperparameters.json").write_text(
        json.dumps(report["hyperparameters"], indent=2), encoding="utf-8"
    )


def main() -> None:
    """Parse arguments and run one training configuration."""
    parser = argparse.ArgumentParser(
        description="Leakage-free training on the official UNSW-NB15 partition."
    )
    parser.add_argument("--data-dir", type=Path, default=Path("/mnt/f/XAI Project/data"))
    parser.add_argument("--results-dir", type=Path, default=Path("/mnt/f/XAI Project/results"))
    parser.add_argument(
        "--artifacts-dir", type=Path, default=Path("/mnt/f/XAI Project/artifacts")
    )
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--validation-size", type=float, default=0.2)
    parser.add_argument("--n-features", type=int, default=25)
    parser.add_argument(
        "--holdout-class",
        type=str,
        default=None,
        help="Class removed from training and validation, present only at test time.",
    )
    parser.add_argument(
        "--smote-strategy",
        type=str,
        default="moderate",
        choices=["full", "moderate", "minimal"],
        help="Chosen on validation data only. See resolve_sampling_strategy.",
    )
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    report = run(args)

    natural = report["metrics_natural"]
    print(f"config              : {report['config']}")
    print(f"seed                : {report['seed']}")
    print(f"holdout class       : {report['holdout_class']}")
    print(f"train rows          : {report['split']['train_rows']}")
    print(f"train rows post SMOTE: {report['split']['train_rows_after_smote']}")
    print(f"validation rows     : {report['split']['validation_rows']}")
    print(f"test rows           : {report['split']['test_rows']}")
    print(f"selected features   : {report['features']['selected_feature_count']}")
    print(f"epochs run          : {report['training']['epochs_run']}")
    print(f"accuracy            : {natural['accuracy']:.4f}")
    print(f"macro F1            : {natural['macro_f1']:.4f}")
    print(f"weighted F1         : {natural['weighted_f1']:.4f}")
    print(f"FPR normal as attack: {natural['false_positive_rate_normal_as_attack']:.4f}")


if __name__ == "__main__":
    main()
