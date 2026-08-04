"""
Module: Enigma-ML-Layer/run_level3_experiments.py

Runs the full Level 3 experiment grid and writes the combined summary.

Grid: five seeds crossed with the closed-set and open-set configurations. The
open-set configuration removes one attack class from training and validation
entirely, leaving it present only in the test partition. That is the unknown
attack condition Level 4 and Level 9 depend on.

The leakage trigger from the brief is enforced here: any run exceeding the
stated accuracy ceiling on the official split halts the grid rather than being
reported, because on this benchmark a high number is more likely to be a bug
than a result.
"""

from __future__ import annotations

import argparse
import csv
import json
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

from train_level3 import run

LEAKAGE_ACCURACY_CEILING = 0.85

SUMMARY_COLUMNS = [
    "config",
    "seed",
    "holdout_class",
    "smote_strategy",
    "distribution",
    "accuracy",
    "macro_f1",
    "weighted_f1",
    "false_positive_rate_normal_as_attack",
    "mean_predicted_confidence",
    "sample_count",
    "selected_feature_count",
    "epochs_run",
    "train_rows",
    "train_rows_after_smote",
]


def summary_rows(report: dict) -> list[dict]:
    """Flatten one run report into summary rows, one per evaluated distribution.

    Args:
        report: A run report from train_level3.run.

    Returns:
        One row per distribution, ready for the summary CSV.
    """
    rows = []
    for distribution, metrics in (
        ("validation", report["metrics_validation"]),
        ("natural", report["metrics_natural"]),
        ("balanced", report["metrics_balanced"]),
    ):
        rows.append(
            {
                "config": report["config"],
                "seed": report["seed"],
                "holdout_class": report["holdout_class"] or "",
                "smote_strategy": report["hyperparameters"]["smote_strategy"],
                "distribution": distribution,
                "accuracy": round(metrics["accuracy"], 6),
                "macro_f1": round(metrics["macro_f1"], 6),
                "weighted_f1": round(metrics["weighted_f1"], 6),
                "false_positive_rate_normal_as_attack": (
                    round(metrics["false_positive_rate_normal_as_attack"], 6)
                    if metrics["false_positive_rate_normal_as_attack"] is not None
                    else ""
                ),
                "mean_predicted_confidence": round(metrics["mean_predicted_confidence"], 6),
                "sample_count": metrics["sample_count"],
                "selected_feature_count": report["features"]["selected_feature_count"],
                "epochs_run": report["training"]["epochs_run"],
                "train_rows": report["split"]["train_rows"],
                "train_rows_after_smote": report["split"]["train_rows_after_smote"],
            }
        )
    return rows


def aggregate(rows: list[dict]) -> dict:
    """Compute mean and standard deviation per config and distribution.

    Args:
        rows: Flattened summary rows across every run.

    Returns:
        Nested statistics keyed by config then distribution.
    """
    import statistics

    grouped: dict[tuple[str, str], list[dict]] = {}
    for row in rows:
        grouped.setdefault((row["config"], row["distribution"]), []).append(row)

    statistics_by_group: dict[str, dict] = {}
    for (config, distribution), group in sorted(grouped.items()):
        entry = statistics_by_group.setdefault(config, {})
        entry[distribution] = {}
        for metric in ("accuracy", "macro_f1", "weighted_f1"):
            values = [row[metric] for row in group]
            entry[distribution][metric] = {
                "mean": round(statistics.fmean(values), 6),
                "std": round(statistics.pstdev(values), 6) if len(values) > 1 else 0.0,
                "min": round(min(values), 6),
                "max": round(max(values), 6),
                "n": len(values),
            }
        rates = [
            row["false_positive_rate_normal_as_attack"]
            for row in group
            if row["false_positive_rate_normal_as_attack"] != ""
        ]
        if rates:
            entry[distribution]["false_positive_rate_normal_as_attack"] = {
                "mean": round(statistics.fmean(rates), 6),
                "std": round(statistics.pstdev(rates), 6) if len(rates) > 1 else 0.0,
                "n": len(rates),
            }
    return statistics_by_group


def main() -> None:
    """Run the grid, write summary.csv and enforce the leakage trigger."""
    parser = argparse.ArgumentParser(description="Run the Level 3 experiment grid.")
    parser.add_argument("--data-dir", type=Path, default=Path("/mnt/f/XAI Project/data"))
    parser.add_argument("--results-dir", type=Path, default=Path("/mnt/f/XAI Project/results"))
    parser.add_argument(
        "--artifacts-dir", type=Path, default=Path("/mnt/f/XAI Project/artifacts")
    )
    parser.add_argument("--seeds", type=int, nargs="*", default=[42, 123, 456, 789, 1024])
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--validation-size", type=float, default=0.2)
    parser.add_argument("--n-features", type=int, default=25)
    parser.add_argument("--holdout-class", type=str, default="Worms")
    parser.add_argument("--smote-strategy", type=str, default="moderate")
    args = parser.parse_args()

    all_rows: list[dict] = []
    ceiling_breaches: list[dict] = []

    for seed in args.seeds:
        for holdout in (None, args.holdout_class):
            run_args = SimpleNamespace(
                data_dir=args.data_dir,
                results_dir=args.results_dir,
                artifacts_dir=args.artifacts_dir,
                seed=seed,
                validation_size=args.validation_size,
                n_features=args.n_features,
                holdout_class=holdout,
                smote_strategy=args.smote_strategy,
                verbose=False,
            )
            report = run(run_args)
            rows = summary_rows(report)
            all_rows.extend(rows)

            natural_accuracy = report["metrics_natural"]["accuracy"]
            config = report["config"]
            print(
                f"{config:<10} seed {seed:<5} "
                f"acc {natural_accuracy:.4f} "
                f"macroF1 {report['metrics_natural']['macro_f1']:.4f} "
                f"FPR {report['metrics_natural']['false_positive_rate_normal_as_attack']:.4f} "
                f"epochs {report['training']['epochs_run']}"
            )

            if natural_accuracy > LEAKAGE_ACCURACY_CEILING:
                ceiling_breaches.append(
                    {"config": config, "seed": seed, "accuracy": natural_accuracy}
                )

    results_dir = args.results_dir / "classifier"
    results_dir.mkdir(parents=True, exist_ok=True)

    summary_path = results_dir / "summary.csv"
    with open(summary_path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=SUMMARY_COLUMNS)
        writer.writeheader()
        writer.writerows(all_rows)

    statistics_by_group = aggregate(all_rows)
    statistics_path = results_dir / "summary_statistics.json"
    statistics_path.write_text(
        json.dumps(
            {
                "generated_at_utc": datetime.now(timezone.utc)
                .isoformat()
                .replace("+00:00", "Z"),
                "seeds": args.seeds,
                "holdout_class": args.holdout_class,
                "smote_strategy": args.smote_strategy,
                "leakage_accuracy_ceiling": LEAKAGE_ACCURACY_CEILING,
                "ceiling_breaches": ceiling_breaches,
                "statistics": statistics_by_group,
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    print()
    print(f"wrote {summary_path}")
    print(f"wrote {statistics_path}")
    print()
    for config, distributions in statistics_by_group.items():
        for distribution, metrics in distributions.items():
            accuracy = metrics["accuracy"]
            macro = metrics["macro_f1"]
            print(
                f"{config:<10} {distribution:<11} "
                f"accuracy {accuracy['mean']:.4f} +/- {accuracy['std']:.4f}   "
                f"macroF1 {macro['mean']:.4f} +/- {macro['std']:.4f}"
            )

    print()
    if ceiling_breaches:
        print(f"LEAKAGE TRIGGER: {len(ceiling_breaches)} run(s) exceeded "
              f"{LEAKAGE_ACCURACY_CEILING:.2f} accuracy")
        for breach in ceiling_breaches:
            print(f"  {breach}")
        raise SystemExit(1)
    print(f"leakage trigger clear: no run exceeded {LEAKAGE_ACCURACY_CEILING:.2f} accuracy")


if __name__ == "__main__":
    main()
