"""
Module: Enigma-ML-Layer/select_smote_strategy.py

Selects the SMOTE resampling strategy using validation data only.

Fully balancing the training fold to the majority count trains under a uniform
class prior while the official test partition is roughly 45 per cent normal.
That prior shift inflates minority predictions and drives the false positive
rate on benign traffic upward, which is the first number an intrusion detection
reviewer looks at. The degree of resampling is therefore a hyperparameter and is
chosen here on the validation split.

The test partition is never loaded for scoring in this module. It is read only
because the training driver requires both files present, and its metrics are
discarded.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

from level3_pipeline import SMOTE_STRATEGIES
from train_level3 import run


def evaluate_strategy(strategy: str, args: argparse.Namespace) -> dict:
    """Train one configuration and report its validation metrics.

    Args:
        strategy: The SMOTE strategy to evaluate.
        args: Base arguments shared by every candidate.

    Returns:
        Validation metrics plus the training row count after resampling.
    """
    run_args = SimpleNamespace(
        data_dir=args.data_dir,
        results_dir=args.results_dir,
        artifacts_dir=args.sweep_artifacts_dir,
        seed=args.seed,
        validation_size=args.validation_size,
        n_features=args.n_features,
        holdout_class=None,
        smote_strategy=strategy,
        verbose=False,
    )
    report = run(run_args)
    validation = report["metrics_validation"]
    return {
        "strategy": strategy,
        "validation_accuracy": validation["accuracy"],
        "validation_macro_f1": validation["macro_f1"],
        "validation_weighted_f1": validation["weighted_f1"],
        "validation_fpr_normal_as_attack": validation["false_positive_rate_normal_as_attack"],
        "train_rows_after_smote": report["split"]["train_rows_after_smote"],
        "epochs_run": report["training"]["epochs_run"],
    }


def main() -> None:
    """Sweep every SMOTE strategy and report the validation winner."""
    parser = argparse.ArgumentParser(
        description="Choose the SMOTE strategy on validation data only."
    )
    parser.add_argument("--data-dir", type=Path, default=Path("/mnt/f/XAI Project/data"))
    parser.add_argument("--results-dir", type=Path, default=Path("/mnt/f/XAI Project/results"))
    parser.add_argument(
        "--sweep-artifacts-dir",
        type=Path,
        default=Path("/mnt/f/XAI Project/artifacts/smote_sweep"),
    )
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--validation-size", type=float, default=0.2)
    parser.add_argument("--n-features", type=int, default=25)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("/mnt/f/XAI Project/results/classifier/smote_strategy_selection.json"),
    )
    args = parser.parse_args()

    candidates = [evaluate_strategy(strategy, args) for strategy in SMOTE_STRATEGIES]
    winner = max(candidates, key=lambda row: row["validation_macro_f1"])

    report = {
        "seed": args.seed,
        "generated_at_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "selection_criterion": "validation macro F1, test partition never consulted",
        "candidates": candidates,
        "selected_strategy": winner["strategy"],
    }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2), encoding="utf-8")

    print(f"wrote {args.output}")
    header = f"{'strategy':<10} {'val_acc':>9} {'val_macroF1':>12} {'val_FPR':>9} {'train_rows':>11}"
    print(header)
    for row in candidates:
        print(
            f"{row['strategy']:<10} {row['validation_accuracy']:>9.4f} "
            f"{row['validation_macro_f1']:>12.4f} "
            f"{row['validation_fpr_normal_as_attack']:>9.4f} "
            f"{row['train_rows_after_smote']:>11}"
        )
    print(f"selected: {winner['strategy']}")


if __name__ == "__main__":
    main()
