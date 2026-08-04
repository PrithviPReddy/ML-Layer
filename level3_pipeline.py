"""
Module: Enigma-ML-Layer/level3_pipeline.py

Leakage-free preprocessing, model construction and evaluation for the official
UNSW-NB15 partition.

Every transform here is a scikit-learn estimator so that fitting is confined to
whatever fold it is shown. The four leakage paths recorded in
paper/EVIDENCE.md section A5 were all caused by fitting on the full dataset
before splitting; expressing each step as a fitted estimator inside an imblearn
Pipeline makes that mistake structurally difficult rather than merely avoided by
discipline.

Column handling notes specific to the official partition:

    id                  dropped, a row index
    label               dropped, perfectly determined by attack_cat and
                        therefore a direct target leak
    attack_cat          the target
    proto service state categorical, one-hot encoded with rare categories
                        collapsed and unseen categories tolerated, because the
                        test partition carries state values absent from the
                        training pool
"""

from __future__ import annotations

from typing import Optional, Sequence

import numpy as np
import pandas as pd
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.compose import ColumnTransformer
from sklearn.feature_selection import SelectKBest, mutual_info_classif
from sklearn.preprocessing import OneHotEncoder, StandardScaler

TARGET_COLUMN = "attack_cat"
DROPPED_COLUMNS = ["id", "label"]
CATEGORICAL_COLUMNS = ["proto", "service", "state"]
NORMAL_CLASS = "Normal"

RARE_CATEGORY_MIN_FREQUENCY = 0.001
IQR_MULTIPLIER = 1.5


class OutlierWinsoriser(BaseEstimator, TransformerMixin):
    """Clip each feature to the interquartile bounds learned from training data.

    The original notebook replaced out-of-bound values with the column median,
    which maps an extreme observation onto a typical one and destroys the very
    signal an intrusion detector depends on. Winsorising preserves the ordering
    of extreme values while bounding their magnitude.

    Bounds are learned in fit and applied in transform, so a fold never sees
    statistics derived from another fold.
    """

    def __init__(self, multiplier: float = IQR_MULTIPLIER) -> None:
        """
        Args:
            multiplier: Interquartile range multiplier defining the bounds.
        """
        self.multiplier = multiplier

    def fit(self, X, y=None) -> "OutlierWinsoriser":
        """Learn lower and upper bounds per feature from the given fold."""
        values = np.asarray(X, dtype=np.float64)
        first_quartile = np.nanpercentile(values, 25, axis=0)
        third_quartile = np.nanpercentile(values, 75, axis=0)
        spread = third_quartile - first_quartile
        self.lower_bounds_ = first_quartile - self.multiplier * spread
        self.upper_bounds_ = third_quartile + self.multiplier * spread
        self.n_features_in_ = values.shape[1]
        return self

    def transform(self, X) -> np.ndarray:
        """Clip to the learned bounds."""
        values = np.asarray(X, dtype=np.float64)
        return np.clip(values, self.lower_bounds_, self.upper_bounds_)


class SeededMutualInformation:
    """Picklable mutual information scorer with a fixed random state.

    SelectKBest stores its score function on the fitted estimator, and the fitted
    pipeline is checkpointed with joblib. A closure over the seed cannot be
    pickled, so the seed is held on an instance instead.
    """

    def __init__(self, seed: int) -> None:
        """
        Args:
            seed: Random state for the nearest neighbour entropy estimator.
        """
        self.seed = seed

    def __call__(self, X, y) -> np.ndarray:
        """Score every feature against the target."""
        return mutual_info_classif(X, y, random_state=self.seed)


def build_column_encoder(numeric_columns: Sequence[str]) -> ColumnTransformer:
    """Assemble the numeric passthrough and categorical one-hot encoder.

    Args:
        numeric_columns: Names of the numeric feature columns.

    Returns:
        A ColumnTransformer that tolerates categories unseen at fit time, which
        is required because the test partition carries state values that the
        training pool does not.
    """
    return ColumnTransformer(
        transformers=[
            ("numeric", "passthrough", list(numeric_columns)),
            (
                "categorical",
                OneHotEncoder(
                    handle_unknown="infrequent_if_exist",
                    min_frequency=RARE_CATEGORY_MIN_FREQUENCY,
                    sparse_output=False,
                ),
                CATEGORICAL_COLUMNS,
            ),
        ],
        remainder="drop",
        verbose_feature_names_out=False,
    )


def build_preprocessor(
    numeric_columns: Sequence[str],
    n_features: int,
    seed: int,
):
    """Build the leakage-free preprocessing pipeline without the resampler.

    Order is encode, select, winsorise, scale. Selection runs before outlier
    handling so that mutual information is measured against the values the
    sensor actually observes rather than against clipped ones.

    Args:
        numeric_columns: Names of the numeric feature columns.
        n_features: How many features mutual information should retain.
        seed: Seed for the mutual information estimator's nearest neighbours.

    Returns:
        A scikit-learn Pipeline of fitted-on-fold transforms.
    """
    from sklearn.pipeline import Pipeline as SklearnPipeline

    return SklearnPipeline(
        steps=[
            ("encode", build_column_encoder(numeric_columns)),
            ("select", SelectKBest(score_func=SeededMutualInformation(seed), k=n_features)),
            ("winsorise", OutlierWinsoriser()),
            ("scale", StandardScaler()),
        ]
    )


SMOTE_STRATEGIES = ("full", "moderate", "minimal")
MODERATE_OVERSAMPLE_FACTOR = 5
MINIMAL_MINORITY_FLOOR = 1000


def resolve_sampling_strategy(strategy: str, class_counts: dict[int, int]) -> object:
    """Translate a named SMOTE strategy into an imblearn sampling_strategy.

    Fully balancing to the majority count trains the model under a uniform class
    prior while the test partition is roughly 45 per cent normal. That prior
    shift systematically inflates minority predictions and therefore the false
    positive rate on benign traffic, which is the metric an intrusion detection
    reviewer weighs most heavily. The named strategies expose that trade-off so
    it can be chosen on validation data rather than assumed.

    Args:
        strategy: One of full, moderate or minimal.
        class_counts: Observed count per encoded class in the training fold.

    Returns:
        A value suitable for SMOTE's sampling_strategy argument.

    Raises:
        ValueError: If the strategy name is not recognised.
    """
    if strategy not in SMOTE_STRATEGIES:
        raise ValueError(f"unknown SMOTE strategy {strategy!r}, expected one of {SMOTE_STRATEGIES}")

    majority = max(class_counts.values())

    if strategy == "full":
        return "auto"

    if strategy == "moderate":
        return {
            label: min(majority, max(count, count * MODERATE_OVERSAMPLE_FACTOR))
            for label, count in class_counts.items()
        }

    return {
        label: min(majority, max(count, MINIMAL_MINORITY_FLOOR))
        for label, count in class_counts.items()
    }


def build_resampling_pipeline(
    numeric_columns: Sequence[str],
    n_features: int,
    seed: int,
    sampling_strategy: object = "auto",
):
    """Build the full pipeline including SMOTE as the terminal step.

    SMOTE sits last and is a sampler, so imblearn applies it during fit_resample
    and skips it entirely during transform. That is what confines synthetic
    samples to the training fold.

    Args:
        numeric_columns: Names of the numeric feature columns.
        n_features: How many features mutual information should retain.
        seed: Seed for both mutual information and SMOTE.
        sampling_strategy: Passed through to SMOTE, from
            resolve_sampling_strategy.

    Returns:
        An imblearn Pipeline whose final step is a sampler.
    """
    from imblearn.over_sampling import SMOTE
    from imblearn.pipeline import Pipeline as ImbalancedPipeline

    preprocessor = build_preprocessor(numeric_columns, n_features, seed)

    return ImbalancedPipeline(
        steps=list(preprocessor.steps)
        + [("resample", SMOTE(random_state=seed, sampling_strategy=sampling_strategy))]
    )


def transform_without_resampling(fitted_pipeline, frame: pd.DataFrame) -> np.ndarray:
    """Apply only the fitted transforms, never the resampler.

    An imblearn Pipeline whose terminal step is a sampler deliberately exposes no
    transform method, because a sampler has nothing sensible to do outside fit.
    Slicing off the final step yields a Pipeline of the already fitted transforms,
    which is what validation and test data must pass through.

    Args:
        fitted_pipeline: A pipeline previously passed to fit_resample.
        frame: Rows to transform.

    Returns:
        The transformed feature matrix, with no synthetic rows added.
    """
    return fitted_pipeline[:-1].transform(frame)


def resolve_numeric_columns(frame: pd.DataFrame) -> list[str]:
    """List the numeric feature columns, excluding the target and the leaks.

    Args:
        frame: A raw partition frame.

    Returns:
        Numeric column names with id, label and attack_cat removed.
    """
    excluded = set(DROPPED_COLUMNS) | {TARGET_COLUMN}
    return [
        column
        for column in frame.columns
        if column not in excluded
        and column not in CATEGORICAL_COLUMNS
        and pd.api.types.is_numeric_dtype(frame[column])
    ]


def selected_feature_names(fitted_pipeline, numeric_columns: Sequence[str]) -> list[str]:
    """Recover the names of the features mutual information retained.

    Args:
        fitted_pipeline: A pipeline whose encode and select steps are fitted.
        numeric_columns: Names of the numeric feature columns.

    Returns:
        Selected feature names in the order the model receives them.
    """
    encoder = fitted_pipeline.named_steps["encode"]
    selector = fitted_pipeline.named_steps["select"]
    all_names = list(encoder.get_feature_names_out())
    mask = selector.get_support()
    return [name for name, keep in zip(all_names, mask) if keep]


def feature_selection_scores(
    fitted_pipeline, numeric_columns: Sequence[str]
) -> list[dict[str, float]]:
    """Report every candidate feature's mutual information score.

    Args:
        fitted_pipeline: A pipeline whose encode and select steps are fitted.
        numeric_columns: Names of the numeric feature columns.

    Returns:
        Feature name, score and retention flag, ordered by descending score.
    """
    encoder = fitted_pipeline.named_steps["encode"]
    selector = fitted_pipeline.named_steps["select"]
    names = list(encoder.get_feature_names_out())
    scores = selector.scores_
    mask = selector.get_support()
    ranked = sorted(
        (
            {"feature": name, "mutual_information": float(score), "selected": bool(keep)}
            for name, score, keep in zip(names, scores, mask)
        ),
        key=lambda row: -row["mutual_information"],
    )
    return ranked


def build_classifier(input_dim: int, num_classes: int, seed: int, hyperparameters: dict):
    """Construct the sensor MLP.

    The architecture is deliberately close to the original notebook's tuned
    model. The classifier is a sensor, not the contribution, so it is not
    re-architected here.

    Args:
        input_dim: Number of input features after selection.
        num_classes: Number of target classes present in training.
        seed: Seed for weight initialisation.
        hyperparameters: Layer widths, dropout rate and learning rate.

    Returns:
        A compiled Keras model.
    """
    import keras

    keras.utils.set_random_seed(seed)

    layers = [keras.layers.Input(shape=(input_dim,))]
    for width in hyperparameters["hidden_units"]:
        layers.append(keras.layers.Dense(width, activation="relu"))
        layers.append(keras.layers.BatchNormalization())
        layers.append(keras.layers.Dropout(hyperparameters["dropout_rate"]))
    layers.append(keras.layers.Dense(num_classes, activation="softmax"))

    model = keras.Sequential(layers)
    model.compile(
        optimizer=keras.optimizers.Adam(learning_rate=hyperparameters["learning_rate"]),
        loss="categorical_crossentropy",
        metrics=["accuracy"],
    )
    return model


def false_positive_rate(
    y_true: np.ndarray, y_pred: np.ndarray, normal_index: Optional[int]
) -> Optional[float]:
    """Fraction of genuinely normal records classified as any attack.

    This is the operational definition an intrusion detection reviewer looks
    for: how often the sensor raises an alert on benign traffic. It is not the
    per-class one-versus-rest false positive rate.

    Args:
        y_true: True class indices.
        y_pred: Predicted class indices.
        normal_index: Index of the normal class, or None when it is absent.

    Returns:
        The rate on the closed unit interval, or None when there are no normal
        records to measure against.
    """
    if normal_index is None:
        return None
    normal_mask = y_true == normal_index
    if not normal_mask.any():
        return None
    return float((y_pred[normal_mask] != normal_index).mean())


def per_class_false_positive_rates(
    y_true: np.ndarray, y_pred: np.ndarray, class_count: int
) -> list[float]:
    """One-versus-rest false positive rate for every class.

    Args:
        y_true: True class indices.
        y_pred: Predicted class indices.
        class_count: Total number of classes.

    Returns:
        A list of rates indexed by class.
    """
    rates = []
    for index in range(class_count):
        negatives = y_true != index
        if not negatives.any():
            rates.append(0.0)
            continue
        rates.append(float((y_pred[negatives] == index).mean()))
    return rates


def balance_by_downsampling(
    frame: pd.DataFrame, target_column: str, seed: int
) -> pd.DataFrame:
    """Downsample every class to the size of the smallest class.

    Used to produce the class-balanced view of the test set. Downsampling is
    used rather than oversampling because synthesising test data would make the
    evaluation partly fictional.

    Args:
        frame: The test partition.
        target_column: Name of the label column.
        seed: Seed controlling which rows are retained.

    Returns:
        A balanced frame.
    """
    smallest = frame[target_column].value_counts().min()
    parts = [
        group.sample(n=smallest, random_state=seed)
        for _, group in frame.groupby(target_column, observed=True)
    ]
    return pd.concat(parts).sample(frac=1.0, random_state=seed).reset_index(drop=True)
