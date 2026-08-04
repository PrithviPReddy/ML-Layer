"""
Module: Enigma-ML-Layer/level4_calibration.py

Calibration, epistemic uncertainty and selective prediction for the Level 3
sensor.

Calibration for network intrusion detection is a saturated topic and is not the
contribution. This module exists so that sensor confidence is trustworthy enough
that abstention observed further up the stack can be attributed to evidence
rather than to a miscalibrated input.

Three design notes worth recording.

**Temperature scaling without stored logits.** The Level 3 models end in a
softmax, so no logits were checkpointed. Taking the elementwise log of the
softmax output recovers the logits up to an additive constant, and softmax is
invariant to an additive constant, so scaling log probabilities by 1/T is exactly
equivalent to scaling the original logits. No retraining and no architecture
change is needed.

**Deep ensemble rather than Monte Carlo dropout.** Level 3 already checkpointed
five independently seeded models per configuration, so the ensemble costs nothing
extra. It is also the stronger estimator. Note that each member carries its own
fitted pipeline, because mutual information feature selection is seeded, so
members differ in both initialisation and input representation. That widens
ensemble diversity rather than compromising it, but it does mean every member
must transform the raw frame itself.

**Uncertainty decomposition.** With an ensemble the predictive entropy of the
mean distribution is total uncertainty, the mean of the member entropies is the
aleatoric part, and their difference is the mutual information, which is the
epistemic part. Only the epistemic part should respond to a class the ensemble
was never trained on.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Sequence

import numpy as np

PROBABILITY_FLOOR = 1e-12
DEFAULT_BIN_COUNT = 15
TEMPERATURE_SEARCH_LOW = 0.05
TEMPERATURE_SEARCH_HIGH = 10.0
TEMPERATURE_SEARCH_STEPS = 400


@dataclass(frozen=True)
class EnsemblePrediction:
    """Per-member and mean probabilities for one evaluation set.

    Attributes:
        member_probabilities: Shape (members, samples, classes).
        mean_probabilities: Shape (samples, classes), the ensemble prediction.
    """

    member_probabilities: np.ndarray
    mean_probabilities: np.ndarray

    @property
    def member_count(self) -> int:
        """Number of ensemble members."""
        return int(self.member_probabilities.shape[0])

    @property
    def predictions(self) -> np.ndarray:
        """Argmax class index of the ensemble mean."""
        return np.argmax(self.mean_probabilities, axis=1)

    @property
    def confidence(self) -> np.ndarray:
        """Maximum ensemble mean probability per sample."""
        return np.max(self.mean_probabilities, axis=1)


def safe_log(probabilities: np.ndarray) -> np.ndarray:
    """Natural log with a floor, so a zero probability cannot produce negative infinity."""
    return np.log(np.clip(probabilities, PROBABILITY_FLOOR, 1.0))


def softmax(scores: np.ndarray) -> np.ndarray:
    """Row-wise softmax, shifted for numerical stability."""
    shifted = scores - np.max(scores, axis=1, keepdims=True)
    exponentiated = np.exp(shifted)
    return exponentiated / np.sum(exponentiated, axis=1, keepdims=True)


def apply_temperature(probabilities: np.ndarray, temperature: float) -> np.ndarray:
    """Rescale a probability matrix by a temperature.

    Args:
        probabilities: Softmax output, shape (samples, classes).
        temperature: Positive scalar. Values above one soften the distribution.

    Returns:
        The temperature-scaled probability matrix.
    """
    return softmax(safe_log(probabilities) / temperature)


def negative_log_likelihood(probabilities: np.ndarray, labels: np.ndarray) -> float:
    """Mean negative log likelihood of the true class."""
    chosen = probabilities[np.arange(len(labels)), labels]
    return float(-np.mean(safe_log(chosen)))


def fit_temperature(
    probabilities: np.ndarray,
    labels: np.ndarray,
    low: float = TEMPERATURE_SEARCH_LOW,
    high: float = TEMPERATURE_SEARCH_HIGH,
    steps: int = TEMPERATURE_SEARCH_STEPS,
) -> tuple[float, float, float]:
    """Fit a single temperature by minimising validation negative log likelihood.

    A dense one dimensional grid search is used rather than gradient descent. The
    objective is smooth and unimodal in one variable, the grid is cheap, and a
    deterministic search removes optimiser seed sensitivity from a number the
    paper reports.

    Args:
        probabilities: Validation softmax output.
        labels: Validation true class indices.
        low: Lowest temperature considered.
        high: Highest temperature considered.
        steps: Grid resolution.

    Returns:
        The fitted temperature, the negative log likelihood before scaling and
        the negative log likelihood after scaling.
    """
    grid = np.linspace(low, high, steps)
    losses = [negative_log_likelihood(apply_temperature(probabilities, value), labels) for value in grid]
    best_index = int(np.argmin(losses))
    return float(grid[best_index]), negative_log_likelihood(probabilities, labels), float(losses[best_index])


def expected_calibration_error(
    probabilities: np.ndarray,
    labels: np.ndarray,
    bin_count: int = DEFAULT_BIN_COUNT,
) -> dict:
    """Top-label expected calibration error with equal-width confidence bins.

    Args:
        probabilities: Softmax output.
        labels: True class indices.
        bin_count: Number of equal-width bins across the confidence range.

    Returns:
        The scalar error, the maximum single-bin gap, and per-bin detail suitable
        for a reliability diagram.
    """
    confidence = np.max(probabilities, axis=1)
    predictions = np.argmax(probabilities, axis=1)
    correct = (predictions == labels).astype(np.float64)

    edges = np.linspace(0.0, 1.0, bin_count + 1)
    total = len(labels)
    error = 0.0
    maximum_gap = 0.0
    bins = []

    for index in range(bin_count):
        lower, upper = edges[index], edges[index + 1]
        in_bin = (confidence > lower) & (confidence <= upper)
        if index == 0:
            in_bin = in_bin | (confidence == 0.0)
        count = int(in_bin.sum())
        if count == 0:
            bins.append(
                {
                    "lower": float(lower),
                    "upper": float(upper),
                    "count": 0,
                    "mean_confidence": None,
                    "accuracy": None,
                    "gap": None,
                }
            )
            continue
        bin_confidence = float(confidence[in_bin].mean())
        bin_accuracy = float(correct[in_bin].mean())
        gap = abs(bin_accuracy - bin_confidence)
        error += (count / total) * gap
        maximum_gap = max(maximum_gap, gap)
        bins.append(
            {
                "lower": float(lower),
                "upper": float(upper),
                "count": count,
                "mean_confidence": bin_confidence,
                "accuracy": bin_accuracy,
                "gap": float(gap),
            }
        )

    return {
        "expected_calibration_error": float(error),
        "maximum_calibration_error": float(maximum_gap),
        "bin_count": bin_count,
        "sample_count": total,
        "bins": bins,
    }


def per_class_calibration_error(
    probabilities: np.ndarray,
    labels: np.ndarray,
    class_names: Sequence[str],
    bin_count: int = DEFAULT_BIN_COUNT,
) -> dict[str, dict]:
    """One-versus-rest calibration error for every class.

    Minority class miscalibration is reported separately because it is the
    mechanism the downstream sanity gate is meant to absorb, and a single
    top-label figure hides it entirely.

    Args:
        probabilities: Softmax output.
        labels: True class indices.
        class_names: Class names ordered by index.
        bin_count: Number of confidence bins.

    Returns:
        Calibration detail keyed by class name.
    """
    results: dict[str, dict] = {}
    edges = np.linspace(0.0, 1.0, bin_count + 1)

    for index, name in enumerate(class_names):
        class_probability = probabilities[:, index]
        is_class = (labels == index).astype(np.float64)
        total = len(labels)
        error = 0.0

        for bin_index in range(bin_count):
            lower, upper = edges[bin_index], edges[bin_index + 1]
            in_bin = (class_probability > lower) & (class_probability <= upper)
            if bin_index == 0:
                in_bin = in_bin | (class_probability == 0.0)
            count = int(in_bin.sum())
            if count == 0:
                continue
            error += (count / total) * abs(
                float(is_class[in_bin].mean()) - float(class_probability[in_bin].mean())
            )

        results[name] = {
            "expected_calibration_error": float(error),
            "support": int(is_class.sum()),
            "mean_predicted_probability": float(class_probability.mean()),
            "observed_frequency": float(is_class.mean()),
        }

    return results


def normalised_entropy(probabilities: np.ndarray) -> np.ndarray:
    """Row-wise Shannon entropy divided by log of the class count."""
    class_count = probabilities.shape[1]
    if class_count <= 1:
        return np.zeros(probabilities.shape[0])
    entropy = -np.sum(probabilities * safe_log(probabilities), axis=1)
    return entropy / np.log(class_count)


def uncertainty_decomposition(prediction: EnsemblePrediction) -> dict[str, np.ndarray]:
    """Split total predictive uncertainty into aleatoric and epistemic parts.

    Args:
        prediction: Ensemble member and mean probabilities.

    Returns:
        total, aleatoric and epistemic arrays, all normalised to the unit
        interval by dividing through by the log of the class count.
    """
    total = normalised_entropy(prediction.mean_probabilities)
    member_entropies = np.stack(
        [normalised_entropy(member) for member in prediction.member_probabilities]
    )
    aleatoric = member_entropies.mean(axis=0)
    epistemic = np.clip(total - aleatoric, 0.0, None)
    return {"total": total, "aleatoric": aleatoric, "epistemic": epistemic}


def risk_coverage_curve(
    scores: np.ndarray,
    correct: np.ndarray,
    steps: int = 100,
) -> dict:
    """Risk against coverage as a rejection threshold sweeps, plus AURC.

    Higher scores must mean higher confidence, so an uncertainty measure should
    be negated before being passed in.

    Args:
        scores: Retention score per sample, higher means keep.
        correct: Boolean correctness per sample.
        steps: Number of coverage points to evaluate.

    Returns:
        The curve as parallel lists, the area under it, and the risk at full
        coverage for reference.
    """
    order = np.argsort(-scores, kind="stable")
    ordered_correct = correct[order].astype(np.float64)
    cumulative_errors = np.cumsum(1.0 - ordered_correct)
    sample_count = len(scores)

    coverages = []
    risks = []
    for step in range(1, steps + 1):
        retained = max(1, int(round(sample_count * step / steps)))
        coverages.append(retained / sample_count)
        risks.append(float(cumulative_errors[retained - 1] / retained))

    area = float(np.trapezoid(risks, coverages))
    return {
        "coverage": coverages,
        "risk": risks,
        "aurc": area,
        "risk_at_full_coverage": float(cumulative_errors[-1] / sample_count),
        "sample_count": sample_count,
    }


def separation_auroc(known_scores: np.ndarray, holdout_scores: np.ndarray) -> Optional[float]:
    """Area under the ROC for separating held-out from known records.

    Computed from the Mann-Whitney U statistic, which needs no threshold sweep
    and handles ties correctly. A value of 0.5 means the score carries no signal
    about whether a record belongs to an unseen class.

    Args:
        known_scores: Uncertainty scores for records of known classes.
        holdout_scores: Uncertainty scores for records of the held-out class.

    Returns:
        The area, or None when either group is empty.
    """
    if len(known_scores) == 0 or len(holdout_scores) == 0:
        return None
    combined = np.concatenate([holdout_scores, known_scores])
    ranks = combined.argsort().argsort().astype(np.float64) + 1.0

    unique_values, inverse, counts = np.unique(combined, return_inverse=True, return_counts=True)
    for value_index, count in enumerate(counts):
        if count > 1:
            mask = inverse == value_index
            ranks[mask] = ranks[mask].mean()

    holdout_rank_sum = ranks[: len(holdout_scores)].sum()
    u_statistic = holdout_rank_sum - len(holdout_scores) * (len(holdout_scores) + 1) / 2.0
    return float(u_statistic / (len(holdout_scores) * len(known_scores)))


def load_ensemble(artifacts_dir: Path, config: str, seeds: Sequence[int]) -> list[dict]:
    """Load every ensemble member's model and fitted pipeline.

    Args:
        artifacts_dir: Directory holding the Level 3 checkpoints.
        config: Either closedset or openset.
        seeds: Member seeds.

    Returns:
        One dict per member carrying its seed, model, pipeline and label encoder.

    Raises:
        FileNotFoundError: If any member's checkpoint is missing.
    """
    import joblib
    from tensorflow.keras.models import load_model

    members = []
    for seed in seeds:
        model_path = artifacts_dir / f"model_{config}_seed{seed}.keras"
        pipeline_path = artifacts_dir / f"pipeline_{config}_seed{seed}.pkl"
        if not model_path.exists() or not pipeline_path.exists():
            raise FileNotFoundError(f"missing ensemble member for seed {seed} of {config}")
        state = joblib.load(pipeline_path)
        members.append(
            {
                "seed": seed,
                "model": load_model(model_path),
                "pipeline": state["pipeline"],
                "label_encoder": state["label_encoder"],
            }
        )
    return members


def predict_ensemble(members: Sequence[dict], frame) -> EnsemblePrediction:
    """Run every member over the same raw frame and average the probabilities.

    Each member transforms the frame with its own fitted pipeline, because
    feature selection is seeded and therefore differs between members.

    Args:
        members: Loaded ensemble members.
        frame: Raw records to score.

    Returns:
        Member and mean probabilities.
    """
    member_probabilities = []
    for member in members:
        features = member["pipeline"][:-1].transform(frame)
        member_probabilities.append(member["model"].predict(features, verbose=0))
    stacked = np.stack(member_probabilities)
    return EnsemblePrediction(member_probabilities=stacked, mean_probabilities=stacked.mean(axis=0))
