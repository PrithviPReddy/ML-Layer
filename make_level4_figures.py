"""
Module: Enigma-ML-Layer/make_level4_figures.py

Renders the Level 4 publication figures as PDF.

Two figures, two different jobs.

The reliability diagram compares predicted confidence against observed accuracy,
so the reference is the diagonal and the readable quantity is the signed gap from
it. Bars are drawn against that diagonal rather than as free-floating heights.

The risk-coverage curve compares three rejection scores on one axis pair, so it
is a three series line chart and takes categorical slots one, two and three,
which are the three slots validated for all-pairs separation rather than only
adjacent pairs.

Print figures, so the interaction and dark mode parts of the visualisation method
do not apply.
"""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

import matplotlib
import numpy as np

matplotlib.use("Agg")

import matplotlib.pyplot as plt

SERIES_ONE = "#2a78d6"
SERIES_TWO = "#eb6834"
SERIES_THREE = "#1baf7a"
INK_PRIMARY = "#0b0b0b"
INK_SECONDARY = "#52514e"
INK_MUTED = "#898781"
GRIDLINE = "#e1e0d9"
AXIS_LINE = "#c3c2b7"
SURFACE = "#fcfcfb"

LINE_WIDTH = 2.0

SCORE_LABELS = {
    "calibrated_confidence": "Calibrated confidence",
    "negative_total_uncertainty": "Total uncertainty",
    "negative_epistemic_uncertainty": "Epistemic uncertainty",
}
SCORE_COLOURS = {
    "calibrated_confidence": SERIES_ONE,
    "negative_total_uncertainty": SERIES_TWO,
    "negative_epistemic_uncertainty": SERIES_THREE,
}


def apply_house_style() -> None:
    """Set the recessive chrome the visualisation method calls for."""
    plt.rcParams.update(
        {
            "figure.facecolor": SURFACE,
            "axes.facecolor": SURFACE,
            "savefig.facecolor": SURFACE,
            "font.family": "sans-serif",
            "font.size": 9,
            "axes.labelcolor": INK_SECONDARY,
            "axes.edgecolor": AXIS_LINE,
            "axes.titlecolor": INK_PRIMARY,
            "axes.titlesize": 10,
            "axes.titleweight": "semibold",
            "xtick.color": INK_MUTED,
            "ytick.color": INK_MUTED,
            "xtick.labelcolor": INK_SECONDARY,
            "ytick.labelcolor": INK_SECONDARY,
            "grid.color": GRIDLINE,
            "grid.linewidth": 0.6,
            "legend.frameon": False,
            "legend.fontsize": 8,
            "figure.dpi": 150,
        }
    )


def tidy(axis) -> None:
    """Drop the top and right spines and put the grid behind the marks."""
    axis.grid(True, linewidth=0.6)
    axis.set_axisbelow(True)
    axis.spines["top"].set_visible(False)
    axis.spines["right"].set_visible(False)


def draw_reliability(report: dict, output: Path, config: str) -> None:
    """Plot observed accuracy against predicted confidence, before and after scaling.

    Args:
        report: One configuration's Level 4 report.
        output: Destination path.
        config: Configuration name, used in the title.
    """
    before = report["calibration"]["test_before"]
    after = report["calibration"]["test_after"]

    figure, axes = plt.subplots(1, 2, figsize=(7.0, 3.2), constrained_layout=True)

    for axis, panel, label, colour in (
        (axes[0], before, "Before scaling", SERIES_ONE),
        (axes[1], after, "After scaling", SERIES_TWO),
    ):
        centres = []
        accuracies = []
        confidences = []
        weights = []
        for entry in panel["bins"]:
            if entry["count"] == 0:
                continue
            centres.append((entry["lower"] + entry["upper"]) / 2.0)
            accuracies.append(entry["accuracy"])
            confidences.append(entry["mean_confidence"])
            weights.append(entry["count"])

        axis.plot([0, 1], [0, 1], color=INK_MUTED, linewidth=1.0, linestyle="--", zorder=1)
        axis.plot(
            confidences,
            accuracies,
            color=colour,
            linewidth=LINE_WIDTH,
            marker="o",
            markersize=4,
            markeredgecolor=SURFACE,
            markeredgewidth=1.0,
            zorder=3,
        )
        axis.vlines(
            confidences,
            confidences,
            accuracies,
            color=colour,
            alpha=0.35,
            linewidth=1.2,
            zorder=2,
        )
        axis.set_title(
            f"{label}\nECE {panel['expected_calibration_error']:.4f}"
        )
        axis.set_xlabel("Predicted confidence")
        axis.set_xlim(0.0, 1.0)
        axis.set_ylim(0.0, 1.0)
        tidy(axis)

    axes[0].set_ylabel("Observed accuracy")
    figure.suptitle(
        f"Reliability, {config}, deep ensemble on the test partition",
        fontsize=10,
        fontweight="semibold",
        color=INK_PRIMARY,
    )
    figure.savefig(output, bbox_inches="tight")
    plt.close(figure)


def draw_risk_coverage(curve_path: Path, report: dict, output: Path, config: str) -> None:
    """Plot risk against coverage for each rejection score.

    Args:
        curve_path: The risk coverage CSV for this configuration.
        report: One configuration's Level 4 report, for the AURC values.
        output: Destination path.
        config: Configuration name, used in the title.
    """
    series: dict[str, dict[str, list[float]]] = {}
    with open(curve_path, newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            entry = series.setdefault(row["score"], {"coverage": [], "risk": []})
            entry["coverage"].append(float(row["coverage"]))
            entry["risk"].append(float(row["risk"]))

    figure, axis = plt.subplots(figsize=(5.2, 3.4), constrained_layout=True)

    for score_name, values in series.items():
        aurc = report["selective_prediction"][score_name]["aurc"]
        axis.plot(
            values["coverage"],
            values["risk"],
            color=SCORE_COLOURS.get(score_name, INK_MUTED),
            linewidth=LINE_WIDTH,
            label=f"{SCORE_LABELS.get(score_name, score_name)}  AURC {aurc:.4f}",
        )

    full_coverage_risk = report["selective_prediction"]["calibrated_confidence"][
        "risk_at_full_coverage"
    ]
    axis.axhline(full_coverage_risk, color=INK_MUTED, linewidth=1.0, linestyle="--")
    axis.annotate(
        f"risk without rejection {full_coverage_risk:.3f}",
        xy=(0.98, full_coverage_risk),
        xytext=(0, -12),
        textcoords="offset points",
        fontsize=7.5,
        color=INK_SECONDARY,
        ha="right",
    )

    axis.set_xlabel("Coverage, share of records retained")
    axis.set_ylabel("Risk, error rate on retained records")
    axis.set_title(f"Risk against coverage, {config}")
    axis.set_xlim(0.0, 1.0)
    axis.legend(loc="upper left")
    tidy(axis)

    figure.savefig(output, bbox_inches="tight")
    plt.close(figure)


def draw_uncertainty_by_class(csv_path: Path, output: Path, config: str) -> None:
    """Plot mean total uncertainty per class, marking the held-out class.

    Args:
        csv_path: The per class uncertainty CSV.
        output: Destination path.
        config: Configuration name, used in the title.
    """
    rows = []
    with open(csv_path, newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            rows.append(row)
    rows.sort(key=lambda entry: float(entry["mean_total"]))

    names = [row["class"] for row in rows]
    totals = [float(row["mean_total"]) for row in rows]
    held_out = [row["in_training"].lower() != "true" for row in rows]
    colours = [SERIES_TWO if flag else SERIES_ONE for flag in held_out]

    figure, axis = plt.subplots(figsize=(5.2, 3.4), constrained_layout=True)
    positions = np.arange(len(names))
    axis.barh(positions, totals, color=colours, height=0.68)
    axis.set_yticks(positions)
    axis.set_yticklabels(names)
    axis.set_xlabel("Mean total predictive uncertainty")
    axis.set_title(f"Uncertainty by class, {config}")
    axis.set_xlim(0.0, max(totals) * 1.25)

    for position, value, flag in zip(positions, totals, held_out):
        axis.text(
            value + max(totals) * 0.02,
            position,
            f"{value:.3f}" + ("  held out" if flag else ""),
            va="center",
            fontsize=7.5,
            color=INK_SECONDARY,
        )

    axis.grid(True, axis="x", linewidth=0.6)
    axis.set_axisbelow(True)
    for spine in ("top", "right", "left"):
        axis.spines[spine].set_visible(False)

    figure.savefig(output, bbox_inches="tight")
    plt.close(figure)


def main() -> None:
    """Render every Level 4 figure."""
    parser = argparse.ArgumentParser(description="Render the Level 4 figures.")
    parser.add_argument("--results-dir", type=Path, default=Path("/mnt/f/XAI Project/results"))
    parser.add_argument("--figures-dir", type=Path, default=Path("/mnt/f/XAI Project/figures"))
    parser.add_argument("--primary-config", type=str, default="openset")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--png-preview", action="store_true")
    args = parser.parse_args()

    apply_house_style()
    args.figures_dir.mkdir(parents=True, exist_ok=True)
    calibration_dir = args.results_dir / "calibration"

    summary = json.loads((calibration_dir / "level4_summary.json").read_text(encoding="utf-8"))
    report = summary["configs"][args.primary_config]

    written = []
    extensions = ["pdf"] + (["png"] if args.png_preview else [])

    for extension in extensions:
        target = args.figures_dir if extension == "pdf" else args.figures_dir / "preview"
        target.mkdir(parents=True, exist_ok=True)

        reliability = target / f"reliability_diagram.{extension}"
        draw_reliability(report, reliability, args.primary_config)
        written.append(reliability)

        risk = target / f"risk_coverage.{extension}"
        draw_risk_coverage(
            calibration_dir / f"risk_coverage_{args.primary_config}.csv",
            report,
            risk,
            args.primary_config,
        )
        written.append(risk)

        uncertainty = target / f"uncertainty_by_class.{extension}"
        draw_uncertainty_by_class(
            calibration_dir / f"uncertainty_by_class_{args.primary_config}.csv",
            uncertainty,
            args.primary_config,
        )
        written.append(uncertainty)

    for path in written:
        print(f"wrote {path}")


if __name__ == "__main__":
    main()
