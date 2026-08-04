"""
Module: Enigma-ML-Layer/tests/test_abstention.py

Unit tests for the Level 4 reject option in the sensor.

The property under test is that temperature scaling applied to a softmax output
is equivalent to scaling the underlying logits, and that the abstention decision
follows the calibrated confidence rather than the raw one.
"""

from __future__ import annotations

import math

import pytest

from scoring import (
    ABSTENTION_SIGNAL_TYPE,
    apply_temperature_to_probabilities,
    decide_abstention,
)


def _sharp(size: int = 10, peak: float = 0.9) -> list[float]:
    """A confident distribution peaking on the first class."""
    remainder = (1.0 - peak) / (size - 1)
    return [peak] + [remainder] * (size - 1)


def _flat(size: int = 10) -> list[float]:
    """A maximally uncertain distribution."""
    return [1.0 / size] * size


class TestTemperatureScaling:
    def test_temperature_of_one_is_identity(self) -> None:
        original = _sharp()
        scaled = apply_temperature_to_probabilities(original, 1.0)
        for before, after in zip(original, scaled):
            assert after == pytest.approx(before, abs=1e-9)

    def test_high_temperature_softens(self) -> None:
        scaled = apply_temperature_to_probabilities(_sharp(), 5.0)
        assert max(scaled) < 0.9

    def test_low_temperature_sharpens(self) -> None:
        scaled = apply_temperature_to_probabilities(_sharp(peak=0.6), 0.25)
        assert max(scaled) > 0.6

    def test_output_is_a_distribution(self) -> None:
        scaled = apply_temperature_to_probabilities(_sharp(), 2.5)
        assert sum(scaled) == pytest.approx(1.0, abs=1e-9)
        assert all(0.0 <= value <= 1.0 for value in scaled)

    def test_uniform_input_is_temperature_invariant(self) -> None:
        for temperature in (0.5, 1.0, 4.0):
            scaled = apply_temperature_to_probabilities(_flat(), temperature)
            assert scaled == pytest.approx(_flat(), abs=1e-9)

    def test_argmax_is_preserved(self) -> None:
        original = [0.05, 0.55, 0.2, 0.2]
        for temperature in (0.2, 1.0, 3.0, 8.0):
            scaled = apply_temperature_to_probabilities(original, temperature)
            assert scaled.index(max(scaled)) == 1

    def test_unnormalised_input_is_renormalised(self) -> None:
        scaled = apply_temperature_to_probabilities([2.0, 6.0, 2.0], 1.0)
        assert sum(scaled) == pytest.approx(1.0, abs=1e-9)
        assert scaled[1] == pytest.approx(0.6, abs=1e-9)

    def test_non_positive_temperature_is_rejected(self) -> None:
        with pytest.raises(ValueError, match="temperature must be positive"):
            apply_temperature_to_probabilities(_sharp(), 0.0)


class TestAbstentionDecision:
    def test_confident_prediction_is_not_abstained(self) -> None:
        decision = decide_abstention(_sharp(peak=0.95), temperature=1.0, confidence_threshold=0.6)
        assert decision["abstained"] is False
        assert decision["calibrated_confidence"] == pytest.approx(0.95, abs=1e-6)

    def test_uncertain_prediction_is_abstained(self) -> None:
        decision = decide_abstention(_flat(), temperature=1.0, confidence_threshold=0.6)
        assert decision["abstained"] is True
        assert decision["calibrated_confidence"] == pytest.approx(0.1, abs=1e-6)

    def test_decision_follows_calibrated_not_raw_confidence(self) -> None:
        """A softening temperature can push a borderline case over the threshold."""
        probabilities = _sharp(peak=0.62)
        raw = decide_abstention(probabilities, temperature=1.0, confidence_threshold=0.6)
        softened = decide_abstention(probabilities, temperature=6.0, confidence_threshold=0.6)
        assert raw["abstained"] is False
        assert softened["abstained"] is True
        assert softened["calibrated_confidence"] < raw["calibrated_confidence"]

    def test_threshold_is_reported_back(self) -> None:
        decision = decide_abstention(_sharp(), temperature=1.0, confidence_threshold=0.42)
        assert decision["confidence_threshold"] == pytest.approx(0.42)

    def test_calibrated_probabilities_are_returned(self) -> None:
        decision = decide_abstention(_sharp(), temperature=2.0, confidence_threshold=0.5)
        assert len(decision["calibrated_probabilities"]) == 10
        assert sum(decision["calibrated_probabilities"]) == pytest.approx(1.0, abs=1e-4)

    def test_threshold_boundary_abstains_below_only(self) -> None:
        probabilities = _sharp(peak=0.5)
        exactly_at = decide_abstention(probabilities, 1.0, confidence_threshold=0.5)
        just_above = decide_abstention(probabilities, 1.0, confidence_threshold=0.500001)
        assert exactly_at["abstained"] is False
        assert just_above["abstained"] is True

    def test_abstention_signal_type_is_the_unknown_label(self) -> None:
        assert ABSTENTION_SIGNAL_TYPE == "unknown"
