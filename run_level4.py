"""
Module: Enigma-ML-Layer/run_level4.py

Runs the Level 4 calibration and selective prediction experiments.

Every fitted quantity comes from the validation split. The temperature is fitted
on validation, the rejection threshold is chosen on validation, and the test
partition is scored once with both already fixed. The held-out class is present
only in the test partition by construction, so the separation experiment cannot
be tuned.

The deep ensemble is the five seeded Level 3 checkpoints for a configuration. It
is used both as the prediction and as the source of the epistemic uncertainty
estimate.
"""

from __future__ import annotations

import argparse
import csv
import json
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split

from level3_pipeline import TARGET_COLUMN
from level4_calibration import (
    apply_temperature,
    expected_calibration_error,
    fit_temperature,
    load_ensemble,
    per_class_calibration_error,
    predict_ensemble,
    risk_coverage_curve,
    separation_auroc,
    uncertainty_decomposition,
)
from train_level3 import POOL_FILENAME, TEST_FILENAME

DEFAULT_SEEDS = [42, 123, 456, 789, 1024]
TARGET_COVERAGE_LEVELS = [0.99, 0.95, 0.90, 0.80, 0.70, 0.50]


def build_validation_split(pool: pd.DataFrame, seed: int, validation_size: float) -> pd.DataFrame:
    """Recreate the validation fold exactly as Level 3 produced it.

    Args:
        pool: The train and validation pool.
        seed: The seed Level 3 used for the split.
        validation_size: The fraction Level 3 held out.

    Returns:
        The validation frame.
    """
    _, validation = train_test_split(
        pool,
        test_size=validation_size,
        random_state=seed,
        stratify=pool[TARGET_COLUMN],
    )
    return validation


def choose_threshold_for_coverage(
    scores: np.ndarray, target_coverage: float
) -> float:
    """Pick the confidence threshold that retains a target fraction on validation.

    Args:
        scores: Retention scores, higher means keep.
        target_coverage: Fraction of records to retain.

    Returns:
        The threshold value.
    """
    return float(np.quantile(scores, 1.0 - target_coverage))


def evaluate_configuration(args: argparse.Namespace, config: str) -> dict:
    """Run every Level 4 measurement for one configuration.

    Args:
        args: Parsed arguments.
        config: Either closedset or openset.

    Returns:
        The full report for this configuration.
    """
    pool = pd.read_csv(args.data_dir / POOL_FILENAME, low_memory=False)
    test = pd.read_csv(args.data_dir / TEST_FILENAME, low_memory=False)

    members = load_ensemble(args.artifacts_dir, config, args.seeds)
    reference_encoder = members[0]["label_encoder"]
    class_names = [str(name) for name in reference_encoder.classes_]

    validation = build_validation_split(pool, args.calibration_seed, args.validation_size)
    validation = validation[validation[TARGET_COLUMN].isin(class_names)]
    y_validation = reference_encoder.transform(validation[TARGET_COLUMN])

    validation_prediction = predict_ensemble(members, validation)
    single_member_validation = validation_prediction.member_probabilities[0]

    temperature, nll_before, nll_after = fit_temperature(
        validation_prediction.mean_probabilities, y_validation
    )
    validation_scaled = apply_temperature(validation_prediction.mean_probabilities, temperature)

    known_mask = test[TARGET_COLUMN].isin(class_names).to_numpy()
    holdout_mask = ~known_mask
    holdout_classes = sorted(set(test.loc[holdout_mask, TARGET_COLUMN].astype(str)))

    test_prediction = predict_ensemble(members, test)
    test_scaled = apply_temperature(test_prediction.mean_probabilities, temperature)

    y_test_known = reference_encoder.transform(test.loc[known_mask, TARGET_COLUMN])
    known_scaled = test_scaled[known_mask]
    known_uncalibrated = test_prediction.mean_probabilities[known_mask]

    calibration = {
        "temperature": temperature,
        "validation_nll_before": nll_before,
        "validation_nll_after": nll_after,
        "validation_before": expected_calibration_error(
            validation_prediction.mean_probabilities, y_validation, args.bins
        ),
        "validation_after": expected_calibration_error(validation_scaled, y_validation, args.bins),
        "validation_single_member_before": expected_calibration_error(
            single_member_validation, y_validation, args.bins
        ),
        "test_before": expected_calibration_error(known_uncalibrated, y_test_known, args.bins),
        "test_after": expected_calibration_error(known_scaled, y_test_known, args.bins),
        "per_class_test_before": per_class_calibration_error(
            known_uncalibrated, y_test_known, class_names, args.bins
        ),
        "per_class_test_after": per_class_calibration_error(
            known_scaled, y_test_known, class_names, args.bins
        ),
    }

    uncertainty = uncertainty_decomposition(test_prediction)
    calibrated_confidence = np.max(test_scaled, axis=1)
    correct_known = (
        np.argmax(known_scaled, axis=1) == y_test_known
    )

    selective = {}
    for label, score in (
        ("calibrated_confidence", calibrated_confidence[known_mask]),
        ("negative_total_uncertainty", -uncertainty["total"][known_mask]),
        ("negative_epistemic_uncertainty", -uncertainty["epistemic"][known_mask]),
    ):
        selective[label] = risk_coverage_curve(score, correct_known)

    validation_uncertainty = uncertainty_decomposition(validation_prediction)
    validation_confidence = np.max(validation_scaled, axis=1)
    thresholds = {
        f"coverage_{int(level * 100)}": {
            "target_coverage": level,
            "threshold_calibrated_confidence": choose_threshold_for_coverage(
                validation_confidence, level
            ),
            "threshold_epistemic_uncertainty": -choose_threshold_for_coverage(
                -validation_uncertainty["epistemic"], level
            ),
        }
        for level in TARGET_COVERAGE_LEVELS
    }

    separation = None
    if holdout_mask.any():
        separation = {
            "holdout_classes": holdout_classes,
            "holdout_count": int(holdout_mask.sum()),
            "known_count": int(known_mask.sum()),
            "auroc": {
                "total_uncertainty": separation_auroc(
                    uncertainty["total"][known_mask], uncertainty["total"][holdout_mask]
                ),
                "aleatoric_uncertainty": separation_auroc(
                    uncertainty["aleatoric"][known_mask], uncertainty["aleatoric"][holdout_mask]
                ),
                "epistemic_uncertainty": separation_auroc(
                    uncertainty["epistemic"][known_mask], uncertainty["epistemic"][holdout_mask]
                ),
                "negative_calibrated_confidence": separation_auroc(
                    -calibrated_confidence[known_mask], -calibrated_confidence[holdout_mask]
                ),
            },
            "statistics": {
                measure: {
                    "known_mean": float(values[known_mask].mean()),
                    "known_median": float(np.median(values[known_mask])),
                    "holdout_mean": float(values[holdout_mask].mean()),
                    "holdout_median": float(np.median(values[holdout_mask])),
                    "gap_holdout_minus_known": float(
                        values[holdout_mask].mean() - values[known_mask].mean()
                    ),
                }
                for measure, values in uncertainty.items()
            },
            "calibrated_confidence": {
                "known_mean": float(calibrated_confidence[known_mask].mean()),
                "holdout_mean": float(calibrated_confidence[holdout_mask].mean()),
                "holdout_max": float(calibrated_confidence[holdout_mask].max()),
            },
            "rejection_at_validation_thresholds": {
                name: {
                    "target_coverage": entry["target_coverage"],
                    "holdout_rejected_share": float(
                        (
                            calibrated_confidence[holdout_mask]
                            < entry["threshold_calibrated_confidence"]
                        ).mean()
                    ),
                    "known_rejected_share": float(
                        (
                            calibrated_confidence[known_mask]
                            < entry["threshold_calibrated_confidence"]
                        ).mean()
                    ),
                }
                for name, entry in thresholds.items()
            },
        }

    uncertainty_by_class = []
    for index, name in enumerate(class_names):
        rows = (test[TARGET_COLUMN] == name).to_numpy()
        if not rows.any():
            continue
        uncertainty_by_class.append(
            {
                "class": name,
                "in_training": True,
                "count": int(rows.sum()),
                "mean_total": float(uncertainty["total"][rows].mean()),
                "mean_aleatoric": float(uncertainty["aleatoric"][rows].mean()),
                "mean_epistemic": float(uncertainty["epistemic"][rows].mean()),
                "mean_calibrated_confidence": float(calibrated_confidence[rows].mean()),
            }
        )
    for name in holdout_classes:
        rows = (test[TARGET_COLUMN] == name).to_numpy()
        uncertainty_by_class.append(
            {
                "class": name,
                "in_training": False,
                "count": int(rows.sum()),
                "mean_total": float(uncertainty["total"][rows].mean()),
                "mean_aleatoric": float(uncertainty["aleatoric"][rows].mean()),
                "mean_epistemic": float(uncertainty["epistemic"][rows].mean()),
                "mean_calibrated_confidence": float(calibrated_confidence[rows].mean()),
            }
        )

    return {
        "config": config,
        "seeds": list(args.seeds),
        "calibration_seed": args.calibration_seed,
        "class_names": class_names,
        "ensemble_member_count": len(members),
        "calibration": calibration,
        "selective_prediction": selective,
        "validation_thresholds": thresholds,
        "separation": separation,
        "uncertainty_by_class": uncertainty_by_class,
    }


def write_outputs(args: argparse.Namespace, report: dict) -> None:
    """Write the JSON report and the two CSV tables for one configuration."""
    config = report["config"]
    results_dir = args.results_dir / "calibration"
    results_dir.mkdir(parents=True, exist_ok=True)

    (results_dir / f"ece_{config}_seed{args.calibration_seed}.json").write_text(
        json.dumps(report, indent=2), encoding="utf-8"
    )

    with open(
        results_dir / f"risk_coverage_{config}.csv", "w", newline="", encoding="utf-8"
    ) as handle:
        writer = csv.writer(handle)
        writer.writerow(["score", "coverage", "risk"])
        for score_name, curve in report["selective_prediction"].items():
            for coverage, risk in zip(curve["coverage"], curve["risk"]):
                writer.writerow([score_name, round(coverage, 6), round(risk, 6)])

    with open(
        results_dir / f"uncertainty_by_class_{config}.csv", "w", newline="", encoding="utf-8"
    ) as handle:
        fieldnames = [
            "class",
            "in_training",
            "count",
            "mean_total",
            "mean_aleatoric",
            "mean_epistemic",
            "mean_calibrated_confidence",
        ]
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(report["uncertainty_by_class"])


def write_abstention_policy(args: argparse.Namespace, report: dict) -> None:
    """Persist the fitted temperature and rejection threshold for the serving path.

    Both quantities come from validation only. Writing them as an artefact rather
    than a constant in the sensor keeps the serving path from silently drifting
    away from the configuration that was measured.

    Args:
        args: Parsed arguments.
        report: The configuration's report.
    """
    config = report["config"]
    coverage_key = f"coverage_{int(args.serving_coverage * 100)}"
    thresholds = report["validation_thresholds"][coverage_key]

    policy = {
        "config": config,
        "generated_at_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "fitted_on": "validation split only",
        "temperature": report["calibration"]["temperature"],
        "target_coverage": thresholds["target_coverage"],
        "confidence_threshold": thresholds["threshold_calibrated_confidence"],
        "class_names": report["class_names"],
        "ensemble_seeds": report["seeds"],
        "measured_known_rejected_share": (
            report["separation"]["rejection_at_validation_thresholds"][coverage_key][
                "known_rejected_share"
            ]
            if report["separation"]
            else None
        ),
        "measured_holdout_rejected_share": (
            report["separation"]["rejection_at_validation_thresholds"][coverage_key][
                "holdout_rejected_share"
            ]
            if report["separation"]
            else None
        ),
    }

    args.artifacts_dir.mkdir(parents=True, exist_ok=True)
    (args.artifacts_dir / f"abstention_policy_{config}.json").write_text(
        json.dumps(policy, indent=2), encoding="utf-8"
    )


def print_report(report: dict) -> None:
    """Print the done check evidence for one configuration."""
    config = report["config"]
    calibration = report["calibration"]

    print(f"===== {config} =====")
    print(f"ensemble members        : {report['ensemble_member_count']}")
    print(f"fitted temperature      : {calibration['temperature']:.4f}")
    print(
        f"validation NLL          : {calibration['validation_nll_before']:.4f} "
        f"-> {calibration['validation_nll_after']:.4f}"
    )
    print(
        f"single member ECE (val) : "
        f"{calibration['validation_single_member_before']['expected_calibration_error']:.4f}"
    )
    print(
        f"ensemble ECE (val)      : "
        f"{calibration['validation_before']['expected_calibration_error']:.4f} "
        f"-> {calibration['validation_after']['expected_calibration_error']:.4f}"
    )
    print(
        f"ensemble ECE (test)     : "
        f"{calibration['test_before']['expected_calibration_error']:.4f} "
        f"-> {calibration['test_after']['expected_calibration_error']:.4f}"
    )
    print(
        f"max calib error (test)  : "
        f"{calibration['test_before']['maximum_calibration_error']:.4f} "
        f"-> {calibration['test_after']['maximum_calibration_error']:.4f}"
    )

    print("  per class ECE on test, before -> after:")
    for name, before in calibration["per_class_test_before"].items():
        after = calibration["per_class_test_after"][name]
        print(
            f"    {name:<16} n={before['support']:<6} "
            f"{before['expected_calibration_error']:.4f} -> "
            f"{after['expected_calibration_error']:.4f}"
        )

    print("  AURC, lower is better:")
    for score_name, curve in report["selective_prediction"].items():
        print(
            f"    {score_name:<32} AURC {curve['aurc']:.4f}   "
            f"risk at full coverage {curve['risk_at_full_coverage']:.4f}"
        )

    separation = report["separation"]
    if separation is None:
        print("  separation: not applicable, no held-out class in this configuration")
        print()
        return

    print(
        f"  separation experiment, holdout {separation['holdout_classes']} "
        f"n={separation['holdout_count']} against known n={separation['known_count']}"
    )
    for measure, value in separation["auroc"].items():
        rendered = "None" if value is None else f"{value:.4f}"
        print(f"    AUROC {measure:<32} {rendered}")
    for measure, statistics in separation["statistics"].items():
        print(
            f"    {measure:<12} known {statistics['known_mean']:.4f}  "
            f"holdout {statistics['holdout_mean']:.4f}  "
            f"gap {statistics['gap_holdout_minus_known']:+.4f}"
        )
    print("    rejection at validation-chosen thresholds:")
    for name, entry in separation["rejection_at_validation_thresholds"].items():
        print(
            f"      {name:<14} target {entry['target_coverage']:.2f}  "
            f"holdout rejected {entry['holdout_rejected_share']:.4f}  "
            f"known rejected {entry['known_rejected_share']:.4f}"
        )
    print()


def main() -> None:
    """Run Level 4 across both configurations."""
    parser = argparse.ArgumentParser(
        description="Level 4 calibration, uncertainty and selective prediction."
    )
    parser.add_argument("--data-dir", type=Path, default=Path("/mnt/f/XAI Project/data"))
    parser.add_argument(
        "--artifacts-dir",
        type=Path,
        default=Path("/mnt/f/XAI Project/artifacts/sensitivity_minimal"),
    )
    parser.add_argument("--results-dir", type=Path, default=Path("/mnt/f/XAI Project/results"))
    parser.add_argument("--seeds", type=int, nargs="*", default=DEFAULT_SEEDS)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--calibration-seed", type=int, default=42)
    parser.add_argument("--validation-size", type=float, default=0.2)
    parser.add_argument("--bins", type=int, default=15)
    parser.add_argument("--configs", type=str, nargs="*", default=["closedset", "openset"])
    parser.add_argument(
        "--serving-coverage",
        type=float,
        default=0.90,
        help="Validation coverage level whose threshold the serving path adopts.",
    )
    args = parser.parse_args()

    reports = []
    for config in args.configs:
        report = evaluate_configuration(args, config)
        write_outputs(args, report)
        reports.append(report)

    for report in reports:
        write_abstention_policy(args, report)

    summary_path = args.results_dir / "calibration" / "level4_summary.json"
    summary_path.write_text(
        json.dumps(
            {
                "seed": args.seed,
                "generated_at_utc": datetime.now(timezone.utc)
                .isoformat()
                .replace("+00:00", "Z"),
                "artifacts_dir": str(args.artifacts_dir),
                "configs": {report["config"]: report for report in reports},
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    print(f"wrote {summary_path}")
    print()
    for report in reports:
        print_report(report)


if __name__ == "__main__":
    main()
