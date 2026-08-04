"""
Module: Enigma-ML-Layer/scoring.py

Turns a classifier's class-probability vector into the three distinct scores the
reasoning layer consumes.

Before Level 2 the sensor emitted a single field named anomaly_score whose value
was the maximum softmax probability. That is the classifier's confidence in
whichever label it picked, not a measure of how anomalous the flow is, so a flow
the model confidently labelled normal scored close to 1. That field is the
0.30-weighted dominant term of the downstream confidence formula, which made the
formula measure detector certainty rather than threat. Recorded as defect D5 in
paper/EVIDENCE.md.

The three scores answer three different questions:

    anomaly_score                is this flow something other than normal
    predicted_class_confidence   how sure is the model about the label it chose
    predictive_entropy           how uncertain is the model overall
"""

from __future__ import annotations

import math
from typing import Iterable, Optional, Sequence

NORMAL_CLASS_NAME = "normal"
PROBABILITY_EPSILON = 1e-12


def resolve_normal_class_index(class_names: Iterable[str]) -> Optional[int]:
    """Locate the index of the normal class within a label ordering.

    Args:
        class_names: Class labels in the order the model emits them.

    Returns:
        The zero-based index of the normal class, or None when the label set
        does not contain one.
    """
    for index, name in enumerate(class_names):
        if str(name).strip().lower() == NORMAL_CLASS_NAME:
            return index
    return None


def normalised_entropy(probabilities: Sequence[float]) -> float:
    """Compute Shannon entropy scaled to the closed unit interval.

    Args:
        probabilities: A class-probability vector. Need not sum exactly to one.

    Returns:
        0.0 for a one-hot distribution, 1.0 for a uniform one. Returns 0.0 when
        there are fewer than two classes, where entropy is undefined.
    """
    count = len(probabilities)
    if count < 2:
        return 0.0

    total = float(sum(probabilities))
    if total <= 0.0:
        return 0.0

    entropy = 0.0
    for value in probabilities:
        probability = float(value) / total
        if probability > PROBABILITY_EPSILON:
            entropy -= probability * math.log(probability)

    return max(0.0, min(entropy / math.log(count), 1.0))


def score_prediction(
    probabilities: Sequence[float],
    normal_class_index: Optional[int],
) -> dict[str, float]:
    """Derive the three sensor scores from one class-probability vector.

    Args:
        probabilities: The model's class-probability vector for one record.
        normal_class_index: Index of the normal class, or None when the label
            set has no normal class. With None the anomaly score falls back to
            one minus the maximum probability, which is the best available
            statement about how unlike any known class the record is.

    Returns:
        A dict with anomaly_score, predicted_class_confidence and
        predictive_entropy, each on the closed unit interval.
    """
    values = [float(value) for value in probabilities]
    total = float(sum(values))
    if total > 0.0:
        values = [value / total for value in values]

    predicted_class_confidence = max(values) if values else 0.0

    if normal_class_index is not None and 0 <= normal_class_index < len(values):
        anomaly_score = 1.0 - values[normal_class_index]
    else:
        anomaly_score = 1.0 - predicted_class_confidence

    return {
        "anomaly_score": round(max(0.0, min(anomaly_score, 1.0)), 6),
        "predicted_class_confidence": round(max(0.0, min(predicted_class_confidence, 1.0)), 6),
        "predictive_entropy": round(normalised_entropy(values), 6),
    }


ABSTENTION_SIGNAL_TYPE = "unknown"


def apply_temperature_to_probabilities(
    probabilities: Sequence[float], temperature: float
) -> list[float]:
    """Rescale a probability vector by a temperature.

    Taking the log of a softmax output recovers the logits up to an additive
    constant, and softmax ignores additive constants, so this is exactly
    temperature scaling of the original logits without needing them stored.

    Args:
        probabilities: The model's class-probability vector.
        temperature: Positive scalar fitted on validation data.

    Returns:
        The rescaled probability vector.
    """
    if temperature <= 0.0:
        raise ValueError(f"temperature must be positive, got {temperature}")

    values = [float(value) for value in probabilities]
    total = sum(values)
    if total > 0.0:
        values = [value / total for value in values]

    scaled_logs = [math.log(max(value, PROBABILITY_EPSILON)) / temperature for value in values]
    highest = max(scaled_logs)
    exponentiated = [math.exp(value - highest) for value in scaled_logs]
    denominator = sum(exponentiated)
    return [value / denominator for value in exponentiated]


def decide_abstention(
    probabilities: Sequence[float],
    temperature: float,
    confidence_threshold: float,
) -> dict:
    """Decide whether the sensor should abstain rather than emit a class label.

    The temperature and the threshold are both fitted on the validation split and
    loaded from the abstention policy artefact, so the serving path cannot drift
    from the configuration that was measured.

    Args:
        probabilities: The model's class-probability vector for one record.
        temperature: Fitted temperature.
        confidence_threshold: Calibrated confidence below which the sensor
            abstains.

    Returns:
        The abstention decision, the calibrated confidence that produced it and
        the calibrated probability vector.
    """
    calibrated = apply_temperature_to_probabilities(probabilities, temperature)
    calibrated_confidence = max(calibrated) if calibrated else 0.0
    abstained = calibrated_confidence < confidence_threshold

    return {
        "abstained": abstained,
        "calibrated_confidence": round(calibrated_confidence, 6),
        "confidence_threshold": round(float(confidence_threshold), 6),
        "calibrated_probabilities": [round(value, 6) for value in calibrated],
    }
