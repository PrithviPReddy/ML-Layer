"""
Module: Enigma-ML-Layer/tests/test_scoring.py

Unit tests for the sensor scoring split introduced in Level 2, defect D5.

The central property under test is that anomaly_score and
predicted_class_confidence measure different things and can diverge sharply. A
flow the model is certain is normal must score near zero on anomaly while
scoring near one on class confidence. The old implementation collapsed both onto
the maximum softmax probability, so this divergence was impossible to express.
"""

from __future__ import annotations

import math

import pytest

from scoring import (
    normalised_entropy,
    resolve_normal_class_index,
    score_prediction,
)

CLASS_NAMES = [
    "analysis",
    "backdoor",
    "dos",
    "exploits",
    "fuzzers",
    "generic",
    "normal",
    "reconnaissance",
    "shellcode",
    "worms",
]
NORMAL_INDEX = 6


def _one_hot(index: int, size: int = 10, peak: float = 0.97) -> list[float]:
    """Build a near one-hot distribution peaking at index."""
    remainder = (1.0 - peak) / (size - 1)
    return [peak if position == index else remainder for position in range(size)]


class TestResolveNormalClassIndex:
    def test_finds_normal_in_alphabetical_ordering(self) -> None:
        assert resolve_normal_class_index(CLASS_NAMES) == NORMAL_INDEX

    def test_is_case_and_whitespace_insensitive(self) -> None:
        assert resolve_normal_class_index(["Attack", " Normal "]) == 1

    def test_returns_none_when_absent(self) -> None:
        assert resolve_normal_class_index(["dos", "worms"]) is None


class TestNormalisedEntropy:
    def test_one_hot_distribution_has_zero_entropy(self) -> None:
        probabilities = [0.0] * 10
        probabilities[3] = 1.0
        assert normalised_entropy(probabilities) == pytest.approx(0.0, abs=1e-9)

    def test_uniform_distribution_has_unit_entropy(self) -> None:
        probabilities = [0.1] * 10
        assert normalised_entropy(probabilities) == pytest.approx(1.0, abs=1e-9)

    def test_entropy_is_bounded(self) -> None:
        assert 0.0 <= normalised_entropy(_one_hot(2)) <= 1.0

    def test_single_class_returns_zero(self) -> None:
        assert normalised_entropy([1.0]) == 0.0

    def test_all_zero_vector_returns_zero(self) -> None:
        assert normalised_entropy([0.0, 0.0, 0.0]) == 0.0


class TestScorePrediction:
    def test_confident_normal_scores_near_zero_anomaly(self) -> None:
        """DONE CHECK item 5, first half, at the sensor rather than the adapter."""
        scores = score_prediction(_one_hot(NORMAL_INDEX, peak=0.97), NORMAL_INDEX)
        assert scores["anomaly_score"] < 0.1
        assert scores["predicted_class_confidence"] > 0.9

    def test_confident_attack_scores_near_one_anomaly(self) -> None:
        """DONE CHECK item 5, second half."""
        generic_index = CLASS_NAMES.index("generic")
        scores = score_prediction(_one_hot(generic_index, peak=0.97), NORMAL_INDEX)
        assert scores["anomaly_score"] > 0.9
        assert scores["predicted_class_confidence"] > 0.9

    def test_the_two_scores_diverge_for_normal(self) -> None:
        """The defect was that these two numbers were always identical."""
        scores = score_prediction(_one_hot(NORMAL_INDEX, peak=0.97), NORMAL_INDEX)
        assert abs(scores["anomaly_score"] - scores["predicted_class_confidence"]) > 0.9

    def test_uncertain_prediction_scores_high_entropy(self) -> None:
        scores = score_prediction([0.1] * 10, NORMAL_INDEX)
        assert scores["predictive_entropy"] > 0.99
        assert scores["anomaly_score"] == pytest.approx(0.9)

    def test_anomaly_score_is_one_minus_probability_of_normal(self) -> None:
        probabilities = [0.0] * 10
        probabilities[NORMAL_INDEX] = 0.4
        probabilities[0] = 0.6
        scores = score_prediction(probabilities, NORMAL_INDEX)
        assert scores["anomaly_score"] == pytest.approx(0.6)

    def test_unnormalised_vector_is_renormalised(self) -> None:
        probabilities = [0.0] * 10
        probabilities[NORMAL_INDEX] = 4.0
        probabilities[0] = 6.0
        scores = score_prediction(probabilities, NORMAL_INDEX)
        assert scores["anomaly_score"] == pytest.approx(0.6)

    def test_missing_normal_class_falls_back_to_one_minus_max(self) -> None:
        scores = score_prediction(_one_hot(2, peak=0.8), None)
        assert scores["anomaly_score"] == pytest.approx(0.2)

    def test_all_scores_are_on_the_unit_interval(self) -> None:
        for index in range(len(CLASS_NAMES)):
            scores = score_prediction(_one_hot(index), NORMAL_INDEX)
            for key, value in scores.items():
                assert 0.0 <= value <= 1.0, f"{key} out of range at class {index}"
