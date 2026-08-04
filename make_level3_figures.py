"""
Module: Enigma-ML-Layer/make_level3_figures.py

Renders the Level 3 publication figures as PDF.

Colour decisions follow the project data visualisation method. The two training
series use categorical slots one and two, validated together: worst adjacent
CVD separation 24.7 and normal vision separation 33.6, both clear of the gates.
The confusion matrix uses the single hue sequential blue ramp light to dark,
never a rainbow, because the quantity encoded is magnitude.

Loss and accuracy are drawn in separate panels rather than on twinned vertical
axes. A dual axis chart invites the reader to compare two unrelated scales by
their crossing point, which is meaningless.

These are print figures, so the interaction and dark mode parts of the method do
not apply. Cell annotations serve the role the table view plays on screen.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import matplotlib
import numpy as np

matplotlib.use("Agg")

import matplotlib.pyplot as plt
from matplotlib.colors import LinearSegmentedColormap

SERIES_TRAIN = "#2a78d6"
SERIES_VALIDATION = "#eb6834"
INK_PRIMARY = "#0b0b0b"
INK_SECONDARY = "#52514e"
INK_MUTED = "#898781"
GRIDLINE = "#e1e0d9"
AXIS_LINE = "#c3c2b7"
SURFACE = "#fcfcfb"

SEQUENTIAL_BLUE_STEPS = [
    "#cde2fb",
    "#b7d3f6",
    "#9ec5f4",
    "#86b6ef",
    "#6da7ec",
    "#5598e7",
    "#3987e5",
    "#2a78d6",
    "#256abf",
    "#1c5cab",
    "#184f95",
    "#104281",
    "#0d366b",
]

LINE_WIDTH = 2.0
MARKER_SIZE = 8.0


def apply_house_style() -> None:
    """Set the recessive chrome the method calls for."""
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


def sequential_colormap() -> LinearSegmentedColormap:
    """Build the single hue blue ramp used for magnitude."""
    return LinearSegmentedColormap.from_list("sequential_blue", SEQUENTIAL_BLUE_STEPS)


def load_report(results_dir: Path, config: str, seed: int) -> dict:
    """Load one run report.

    Args:
        results_dir: The results directory root.
        config: Either closedset or openset.
        seed: The run seed.

    Returns:
        The parsed report.
    """
    path = results_dir / "classifier" / f"metrics_{config}_seed{seed}.json"
    return json.loads(path.read_text(encoding="utf-8"))


def draw_training_curves(report: dict, output: Path) -> None:
    """Plot loss and accuracy against epoch in two panels.

    Args:
        report: A run report carrying the Keras history.
        output: Destination PDF path.
    """
    history = report["training"]["history"]
    epochs = np.arange(1, len(history["loss"]) + 1)

    figure, axes = plt.subplots(1, 2, figsize=(7.0, 2.9), constrained_layout=True)

    axes[0].plot(
        epochs, history["loss"], color=SERIES_TRAIN, linewidth=LINE_WIDTH, label="Train"
    )
    axes[0].plot(
        epochs,
        history["val_loss"],
        color=SERIES_VALIDATION,
        linewidth=LINE_WIDTH,
        label="Validation",
    )
    best_epoch = int(np.argmin(history["val_loss"])) + 1
    axes[0].plot(
        [best_epoch],
        [min(history["val_loss"])],
        marker="o",
        markersize=MARKER_SIZE / 2,
        color=SERIES_VALIDATION,
        markeredgecolor=SURFACE,
        markeredgewidth=1.5,
        linestyle="none",
    )
    axes[0].annotate(
        f"best epoch {best_epoch}",
        xy=(best_epoch, min(history["val_loss"])),
        xytext=(6, 10),
        textcoords="offset points",
        fontsize=7.5,
        color=INK_SECONDARY,
    )
    axes[0].set_title("Cross-entropy loss")
    axes[0].set_xlabel("Epoch")
    axes[0].set_ylabel("Loss")

    axes[1].plot(
        epochs, history["accuracy"], color=SERIES_TRAIN, linewidth=LINE_WIDTH, label="Train"
    )
    axes[1].plot(
        epochs,
        history["val_accuracy"],
        color=SERIES_VALIDATION,
        linewidth=LINE_WIDTH,
        label="Validation",
    )
    axes[1].set_title("Accuracy")
    axes[1].set_xlabel("Epoch")
    axes[1].set_ylabel("Accuracy")

    for axis in axes:
        axis.grid(True, axis="y", linewidth=0.6)
        axis.set_axisbelow(True)
        axis.spines["top"].set_visible(False)
        axis.spines["right"].set_visible(False)

    axes[0].legend(loc="upper right")

    figure.savefig(output, bbox_inches="tight")
    plt.close(figure)


def draw_confusion_matrix(report: dict, output: Path, title: str) -> None:
    """Plot the row-normalised confusion matrix as a single hue heatmap.

    Args:
        report: A run report carrying the normalised matrix and class names.
        output: Destination PDF path.
        title: Figure title.
    """
    matrix = np.array(report["metrics_natural"]["confusion_matrix_normalised"])
    class_names = report["classes"]["training_classes"]

    figure, axis = plt.subplots(figsize=(5.6, 5.0), constrained_layout=True)
    image = axis.imshow(matrix, cmap=sequential_colormap(), vmin=0.0, vmax=1.0)

    axis.set_xticks(np.arange(len(class_names)))
    axis.set_yticks(np.arange(len(class_names)))
    axis.set_xticklabels(class_names, rotation=45, ha="right")
    axis.set_yticklabels(class_names)
    axis.set_xlabel("Predicted")
    axis.set_ylabel("True")
    axis.set_title(title)

    axis.set_xticks(np.arange(len(class_names) + 1) - 0.5, minor=True)
    axis.set_yticks(np.arange(len(class_names) + 1) - 0.5, minor=True)
    axis.grid(which="minor", color=SURFACE, linewidth=1.5)
    axis.tick_params(which="minor", length=0)
    for spine in axis.spines.values():
        spine.set_visible(False)

    for row in range(matrix.shape[0]):
        for column in range(matrix.shape[1]):
            value = matrix[row, column]
            if value < 0.005:
                continue
            axis.text(
                column,
                row,
                f"{value:.2f}",
                ha="center",
                va="center",
                fontsize=7,
                color=SURFACE if value > 0.55 else INK_PRIMARY,
            )

    colourbar = figure.colorbar(image, ax=axis, shrink=0.82)
    colourbar.set_label("Share of true class", color=INK_SECONDARY)
    colourbar.outline.set_visible(False)

    figure.savefig(output, bbox_inches="tight")
    plt.close(figure)


def main() -> None:
    """Render every Level 3 figure."""
    parser = argparse.ArgumentParser(description="Render the Level 3 figures.")
    parser.add_argument("--results-dir", type=Path, default=Path("/mnt/f/XAI Project/results"))
    parser.add_argument("--figures-dir", type=Path, default=Path("/mnt/f/XAI Project/figures"))
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--png-preview", action="store_true")
    args = parser.parse_args()

    apply_house_style()
    args.figures_dir.mkdir(parents=True, exist_ok=True)

    closed = load_report(args.results_dir, "closedset", args.seed)
    written = []

    curves_path = args.figures_dir / f"training_curves_seed{args.seed}.pdf"
    draw_training_curves(closed, curves_path)
    written.append(curves_path)

    closed_matrix_path = args.figures_dir / f"confusion_matrix_closedset_seed{args.seed}.pdf"
    draw_confusion_matrix(
        closed, closed_matrix_path, f"Closed set, seed {args.seed}, natural distribution"
    )
    written.append(closed_matrix_path)

    try:
        opened = load_report(args.results_dir, "openset", args.seed)
    except FileNotFoundError:
        opened = None

    if opened is not None:
        open_matrix_path = args.figures_dir / f"confusion_matrix_openset_seed{args.seed}.pdf"
        draw_confusion_matrix(
            opened,
            open_matrix_path,
            f"Open set, {opened['holdout_class']} held out, seed {args.seed}",
        )
        written.append(open_matrix_path)

    if args.png_preview:
        preview_dir = args.figures_dir / "preview"
        preview_dir.mkdir(parents=True, exist_ok=True)
        for path in list(written):
            preview = preview_dir / f"{path.stem}.png"
            regenerate_as_png(path, preview, args)
            written.append(preview)

    for path in written:
        print(f"wrote {path}")


def regenerate_as_png(pdf_path: Path, png_path: Path, args: argparse.Namespace) -> None:
    """Re-render one figure as PNG so it can be inspected visually.

    Args:
        pdf_path: The PDF that was produced.
        png_path: Destination PNG path.
        args: Parsed arguments, used to reload the source report.
    """
    stem = pdf_path.stem
    if stem.startswith("training_curves"):
        draw_training_curves(load_report(args.results_dir, "closedset", args.seed), png_path)
        return
    config = "openset" if "openset" in stem else "closedset"
    report = load_report(args.results_dir, config, args.seed)
    title = (
        f"Open set, {report['holdout_class']} held out, seed {args.seed}"
        if config == "openset"
        else f"Closed set, seed {args.seed}, natural distribution"
    )
    draw_confusion_matrix(report, png_path, title)


if __name__ == "__main__":
    main()
