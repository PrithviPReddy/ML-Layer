import argparse
import gc
import json
import random
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from imblearn.over_sampling import SMOTE
from imblearn.pipeline import Pipeline as ImbPipeline
from imblearn.under_sampling import RandomUnderSampler
from sklearn.feature_selection import mutual_info_regression
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler

RAW_PARTITION_FILES = [
    "UNSW-NB15_1.csv",
    "UNSW-NB15_2.csv",
    "UNSW-NB15_3.csv",
    "UNSW-NB15_4.csv",
]
FEATURE_SCHEMA_FILE = "NUSW-NB15_features.csv"

NOTEBOOK_DROP_COLUMNS = ["sport", "dsport", "proto", "srcip", "dstip", "state", "service"]
OUTLIER_EXCLUDE_COLUMNS = ["sport", "swim", "dwim", "stcpb", "dtcpb", "Stime", "Ltime"]
CORRELATION_THRESHOLD = 0.75
MUTUAL_INFO_THRESHOLD = 0.01
RESAMPLE_TARGET_PER_CLASS = 15000
NUM_CLASSES = 11


_STAGE_CLOCK = {"start": None}


def stage(message):
    now = datetime.now(timezone.utc)
    if _STAGE_CLOCK["start"] is None:
        _STAGE_CLOCK["start"] = now
    elapsed = (now - _STAGE_CLOCK["start"]).total_seconds()
    print(f"[{elapsed:8.1f}s] {message}", flush=True)


def set_global_seed(seed):
    random.seed(seed)
    np.random.seed(seed)
    import tensorflow as tf

    tf.random.set_seed(seed)
    tf.keras.utils.set_random_seed(seed)


def load_raw_partitions(data_dir):
    schema = pd.read_csv(data_dir / FEATURE_SCHEMA_FILE, encoding="cp1252")
    column_names = [str(name) for name in schema["Name"].tolist()]

    frames = []
    for name in RAW_PARTITION_FILES:
        frame = pd.read_csv(data_dir / name, header=None, names=column_names, low_memory=False)
        frames.append(frame)

    combined = pd.concat(frames, ignore_index=True)
    del frames
    gc.collect()
    return combined


def clean_frame(frame, seed):
    frame = frame.sample(frac=1, random_state=seed).reset_index(drop=True)
    frame = frame.drop_duplicates()

    frame["attack_cat"] = frame["attack_cat"].fillna("normal")
    frame["attack_cat"] = frame["attack_cat"].apply(lambda value: str(value).strip().lower())
    frame["ct_flw_http_mthd"] = frame["ct_flw_http_mthd"].fillna(0)
    frame["is_ftp_login"] = frame["is_ftp_login"].fillna(0)

    frame["ct_ftp_cmd"] = frame["ct_ftp_cmd"].astype("str").replace(" ", "0").astype("int")
    frame["is_ftp_login"] = (frame["is_ftp_login"] > 0).astype(int)

    frame["sport"] = pd.to_numeric(frame["sport"].astype("str"), errors="coerce").fillna(0).astype(int)
    frame["dsport"] = pd.to_numeric(frame["dsport"].astype("str"), errors="coerce").fillna(0).astype(int)
    return frame


def replace_outliers_with_median(frame):
    numerical_columns = frame.select_dtypes(include=["float64", "int64"]).columns.tolist()
    numerical_columns = [c for c in numerical_columns if c not in OUTLIER_EXCLUDE_COLUMNS]

    for column in numerical_columns:
        values = frame[column]
        median_value = values.median()
        q1 = values.quantile(0.25)
        q3 = values.quantile(0.75)
        iqr = q3 - q1
        lower_bound = q1 - 1.5 * iqr
        upper_bound = q3 + 1.5 * iqr
        frame[column] = values.where((values >= lower_bound) & (values <= upper_bound), median_value)
    return frame


def drop_highly_correlated(frame):
    correlation = frame.corr()
    mask = correlation >= CORRELATION_THRESHOLD

    pairs = []
    for feature in mask.columns:
        correlated_with = mask.index[mask[feature]].tolist()
        for other in correlated_with:
            if feature != other and (other, feature) not in pairs:
                pairs.append((feature, other))

    to_drop = set()
    for first, second in pairs:
        if first not in to_drop and second not in to_drop:
            to_drop.add(second)

    return frame.drop(columns=list(to_drop)), sorted(to_drop), pairs


def resample_to_balance(features, target):
    counts = target.value_counts()
    oversample_strategy = {
        index: RESAMPLE_TARGET_PER_CLASS
        for index in range(len(counts))
        if counts[index] < RESAMPLE_TARGET_PER_CLASS
    }
    undersample_strategy = {
        index: RESAMPLE_TARGET_PER_CLASS
        for index in range(len(counts))
        if counts[index] > RESAMPLE_TARGET_PER_CLASS
    }
    pipeline = ImbPipeline(
        steps=[
            ("smote", SMOTE(sampling_strategy=oversample_strategy)),
            ("undersample", RandomUnderSampler(sampling_strategy=undersample_strategy)),
        ]
    )
    return pipeline.fit_resample(features, target)


def mutual_information_scores(features, target):
    discrete_features = features.dtypes == int
    scores = mutual_info_regression(features, target, discrete_features=discrete_features)
    frame = pd.DataFrame({"Features": features.columns, "Scores": scores})
    return frame.sort_values(["Scores"], ascending=False).reset_index(drop=True)


def build_baseline_model():
    from tensorflow.keras.layers import BatchNormalization, Dense
    from tensorflow.keras.models import Sequential
    from tensorflow.keras.regularizers import l2

    model = Sequential()
    model.add(Dense(25, activation="relu", input_dim=20, kernel_regularizer=l2(), kernel_initializer="glorot_uniform"))
    model.add(Dense(18, activation="relu", kernel_regularizer=l2()))
    model.add(BatchNormalization())
    model.add(Dense(12, activation="relu", kernel_regularizer=l2()))
    model.add(BatchNormalization())
    model.add(Dense(NUM_CLASSES, activation="softmax"))
    model.compile(loss="categorical_crossentropy", optimizer="adam", metrics=["accuracy"])
    return model


def make_tuner_model_builder(input_dim):
    import keras
    from tensorflow.keras.layers import BatchNormalization

    def build_model(hp):
        model = keras.Sequential()
        num_of_layer = hp.Int("num_of_layer", min_value=1, max_value=5, step=1)
        model.add(keras.layers.InputLayer(shape=(input_dim,)))
        for index in range(num_of_layer):
            model.add(
                keras.layers.Dense(
                    units=hp.Int(f"unit_{index}_layer", min_value=20, max_value=40, step=2),
                    activation="relu",
                )
            )
            model.add(BatchNormalization())
            model.add(
                keras.layers.Dropout(rate=hp.Float("dropout_rate", min_value=0.1, max_value=0.5, step=0.1))
            )
        model.add(keras.layers.Dense(NUM_CLASSES, activation="softmax"))
        model.compile(
            optimizer=keras.optimizers.Adam(
                learning_rate=hp.Choice("learning_rate", values=[1e-2, 1e-3, 1e-4])
            ),
            loss="categorical_crossentropy",
            metrics=["accuracy"],
        )
        return model

    return build_model


def history_to_dict(history):
    return {key: [float(value) for value in values] for key, values in history.history.items()}


def main():
    parser = argparse.ArgumentParser(
        description="Reproduce the original Model.ipynb training pipeline as an executable script."
    )
    parser.add_argument("--data-dir", type=Path, default=Path(__file__).resolve().parents[1] / "data")
    parser.add_argument("--results-dir", type=Path, default=Path(__file__).resolve().parents[1] / "results")
    parser.add_argument("--artifacts-dir", type=Path, default=Path(__file__).resolve().parents[1] / "artifacts")
    parser.add_argument("--tuner-dir", type=Path, default=Path(__file__).resolve().parents[1] / "artifacts" / "tuner")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--test-size", type=float, default=0.2)
    parser.add_argument("--baseline-epochs", type=int, default=100)
    parser.add_argument("--tuned-epochs", type=int, default=100)
    parser.add_argument("--max-trials", type=int, default=10)
    parser.add_argument("--batch-size", type=int, default=32)
    parser.add_argument("--skip-tuning", action="store_true")
    parser.add_argument("--sample-rows", type=int, default=0)
    parser.add_argument("--run-name", type=str, default="notebook_parity")
    args = parser.parse_args()

    set_global_seed(args.seed)

    import keras
    import keras_tuner
    from tensorflow.keras.utils import to_categorical

    started_at = datetime.now(timezone.utc)
    args.results_dir.mkdir(parents=True, exist_ok=True)
    args.artifacts_dir.mkdir(parents=True, exist_ok=True)

    report = {
        "run_name": args.run_name,
        "seed": args.seed,
        "started_at_utc": started_at.isoformat().replace("+00:00", "Z"),
        "provenance": "faithful port of Model.ipynb, leakage preserved deliberately for Level 1 parity",
        "config": {
            "test_size": args.test_size,
            "baseline_epochs": args.baseline_epochs,
            "tuned_epochs": args.tuned_epochs,
            "max_trials": args.max_trials,
            "batch_size": args.batch_size,
            "skip_tuning": args.skip_tuning,
            "sample_rows": args.sample_rows,
        },
    }

    stage("loading raw partitions")
    frame = load_raw_partitions(args.data_dir)
    report["rows_loaded"] = int(len(frame))
    stage(f"loaded {len(frame)} rows")

    if args.sample_rows > 0:
        frame = frame.sample(n=min(args.sample_rows, len(frame)), random_state=args.seed).reset_index(drop=True)
        report["rows_after_sampling"] = int(len(frame))
        stage(f"sampled to {len(frame)} rows")

    stage("cleaning and deduplicating")
    frame = clean_frame(frame, args.seed)
    report["rows_after_dedup"] = int(len(frame))
    stage(f"{len(frame)} rows after dedup")

    stage("replacing outliers with medians")
    frame = replace_outliers_with_median(frame)
    frame = frame.drop(columns=NOTEBOOK_DROP_COLUMNS)

    stage("encoding labels")
    label_encoder = LabelEncoder()
    frame["attack_cat"] = label_encoder.fit_transform(frame["attack_cat"])
    label_mapping = {
        str(name): int(value)
        for name, value in zip(label_encoder.classes_, label_encoder.transform(label_encoder.classes_))
    }
    report["label_mapping"] = label_mapping
    report["num_classes_observed"] = len(label_mapping)

    stage("dropping highly correlated features")
    frame, correlation_dropped, correlation_pairs = drop_highly_correlated(frame)
    report["correlation_dropped_columns"] = correlation_dropped
    report["correlation_pair_count"] = len(correlation_pairs)
    stage(f"dropped {len(correlation_dropped)} correlated columns from {len(correlation_pairs)} pairs")

    features = frame.drop(["attack_cat"], axis=1)
    target = frame[["attack_cat"]]
    del frame
    gc.collect()

    report["class_distribution_before_resample"] = {
        str(index): int(count) for index, count in target["attack_cat"].value_counts().items()
    }

    stage("resampling with SMOTE and random undersampling")
    features, target = resample_to_balance(features, target)
    report["class_distribution_after_resample"] = {
        str(index): int(count) for index, count in target["attack_cat"].value_counts().items()
    }
    stage(f"resampled to {len(features)} rows")

    stage("scoring mutual information")
    scores = mutual_information_scores(features, target.astype("float64"))
    low_score_features = scores[scores["Scores"] < MUTUAL_INFO_THRESHOLD]["Features"].tolist()
    features = features.drop(low_score_features, axis=1)
    report["mutual_info_scores"] = {
        str(row.Features): float(row.Scores) for row in scores.itertuples()
    }
    report["mutual_info_dropped_columns"] = [str(name) for name in low_score_features]

    final_features = features.columns.tolist()
    report["final_features"] = [str(name) for name in final_features]
    report["final_feature_count"] = len(final_features)

    scaler = StandardScaler()
    features_scaled = scaler.fit_transform(features)

    x_train, x_test, y_train, y_test = train_test_split(
        features_scaled, target, test_size=args.test_size, random_state=args.seed
    )
    y_train_one_hot = to_categorical(y_train["attack_cat"], num_classes=NUM_CLASSES)
    y_test_one_hot = to_categorical(y_test["attack_cat"], num_classes=NUM_CLASSES)
    report["train_rows"] = int(len(x_train))
    report["test_rows"] = int(len(x_test))

    stage(f"training baseline model on {len(x_train)} rows")
    baseline = build_baseline_model()
    baseline_history = baseline.fit(
        x_train,
        y_train_one_hot,
        epochs=args.baseline_epochs,
        batch_size=args.batch_size,
        validation_data=(x_test, y_test_one_hot),
        callbacks=[keras.callbacks.EarlyStopping(patience=5, restore_best_weights=True)],
        verbose=2,
    )
    baseline_loss, baseline_accuracy = baseline.evaluate(x_test, y_test_one_hot, verbose=0)
    report["baseline_model"] = {
        "test_loss": float(baseline_loss),
        "test_accuracy": float(baseline_accuracy),
        "epochs_run": len(baseline_history.history["loss"]),
        "history": history_to_dict(baseline_history),
    }

    if args.skip_tuning:
        report["tuned_model"] = None
        selected_model = baseline
        selected_name = "baseline"
    else:
        tuner = keras_tuner.RandomSearch(
            hypermodel=make_tuner_model_builder(len(final_features)),
            objective="val_accuracy",
            max_trials=args.max_trials,
            max_retries_per_trial=3,
            directory=str(args.tuner_dir),
            project_name="threat_detection_project",
            seed=args.seed,
        )
        tuner.search(
            x_train,
            y_train_one_hot,
            epochs=args.tuned_epochs,
            batch_size=args.batch_size,
            validation_data=(x_test, y_test_one_hot),
            callbacks=[keras.callbacks.EarlyStopping(monitor="val_loss", patience=3)],
        )
        best_hyperparameters = tuner.get_best_hyperparameters(num_trials=1)[0]
        report["best_hyperparameters"] = dict(best_hyperparameters.values)

        tuned = tuner.hypermodel.build(best_hyperparameters)
        tuned_history = tuned.fit(
            x_train,
            y_train_one_hot,
            epochs=args.tuned_epochs,
            batch_size=args.batch_size,
            validation_data=(x_test, y_test_one_hot),
            verbose=2,
        )
        tuned_loss, tuned_accuracy = tuned.evaluate(x_test, y_test_one_hot, verbose=0)
        report["tuned_model"] = {
            "test_loss": float(tuned_loss),
            "test_accuracy": float(tuned_accuracy),
            "epochs_run": len(tuned_history.history["loss"]),
            "history": history_to_dict(tuned_history),
        }
        selected_model = tuned
        selected_name = "tuned"

    report["selected_model"] = selected_name

    model_path_keras = args.artifacts_dir / f"unsw_nb15_threat_detection_model_{args.run_name}_seed{args.seed}.keras"
    model_path_h5 = args.artifacts_dir / "unsw_nb15_threat_detection_model.h5"
    selected_model.save(model_path_keras)
    selected_model.save(model_path_h5)

    pipeline_state = {
        "scaler": scaler,
        "expected_features": final_features,
        "dropped_columns": [str(name) for name in low_score_features],
        "label_encoder": label_encoder,
    }
    pipeline_path = args.artifacts_dir / "unsw_nb15_preprocessing_state.pkl"
    joblib.dump(pipeline_state, pipeline_path)

    class_index_path = args.artifacts_dir / "class_index.json"
    class_index_path.write_text(
        json.dumps({str(value): str(name) for name, value in label_mapping.items()}, indent=2),
        encoding="utf-8",
    )

    finished_at = datetime.now(timezone.utc)
    report["finished_at_utc"] = finished_at.isoformat().replace("+00:00", "Z")
    report["duration_seconds"] = (finished_at - started_at).total_seconds()
    report["artifacts"] = {
        "model_keras": str(model_path_keras),
        "model_h5": str(model_path_h5),
        "pipeline_state": str(pipeline_path),
        "class_index": str(class_index_path),
    }

    report_path = args.results_dir / f"train_{args.run_name}_seed{args.seed}.json"
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    print(f"wrote {report_path}")
    print(f"selected model: {selected_name}")
    print(f"baseline test accuracy: {report['baseline_model']['test_accuracy']:.4f}")
    if report.get("tuned_model"):
        print(f"tuned test accuracy: {report['tuned_model']['test_accuracy']:.4f}")
    print(f"artifacts written to {args.artifacts_dir}")


if __name__ == "__main__":
    main()
