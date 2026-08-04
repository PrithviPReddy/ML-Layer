import argparse
import json
import os
import platform
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path


def collect_nvidia_smi():
    for candidate in ("nvidia-smi", "/usr/lib/wsl/lib/nvidia-smi"):
        try:
            output = subprocess.run(
                [
                    candidate,
                    "--query-gpu=name,memory.total,memory.free,driver_version,compute_cap",
                    "--format=csv,noheader",
                ],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if output.returncode == 0 and output.stdout.strip():
                fields = [field.strip() for field in output.stdout.strip().split(",")]
                return {
                    "name": fields[0],
                    "memory_total": fields[1],
                    "memory_free": fields[2],
                    "driver_version": fields[3],
                    "compute_cap": fields[4] if len(fields) > 4 else None,
                }
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
    return None


def build_model(input_dim, num_classes, seed):
    import keras

    keras.utils.set_random_seed(seed)
    model = keras.Sequential(
        [
            keras.layers.Input(shape=(input_dim,)),
            keras.layers.Dense(32, activation="relu"),
            keras.layers.BatchNormalization(),
            keras.layers.Dropout(0.2),
            keras.layers.Dense(32, activation="relu"),
            keras.layers.BatchNormalization(),
            keras.layers.Dropout(0.2),
            keras.layers.Dense(num_classes, activation="softmax"),
        ]
    )
    model.compile(
        optimizer=keras.optimizers.Adam(learning_rate=1e-3),
        loss="categorical_crossentropy",
        metrics=["accuracy"],
    )
    return model


class EpochTimer:
    def __init__(self):
        self.times = []
        self._start = None

    def make_callback(self):
        import keras

        outer = self

        class Timer(keras.callbacks.Callback):
            def on_epoch_begin(self, epoch, logs=None):
                outer._start = time.perf_counter()

            def on_epoch_end(self, epoch, logs=None):
                outer.times.append(time.perf_counter() - outer._start)

        return Timer()


def main():
    parser = argparse.ArgumentParser(description="Benchmark one identical training run on GPU or CPU.")
    parser.add_argument("--device", choices=["gpu", "cpu"], required=True)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--rows", type=int, default=132000)
    parser.add_argument("--features", type=int, default=20)
    parser.add_argument("--classes", type=int, default=11)
    parser.add_argument("--epochs", type=int, default=10)
    parser.add_argument("--batch-size", type=int, default=32)
    parser.add_argument("--output", type=Path, default=None)
    args = parser.parse_args()

    if args.device == "cpu":
        os.environ["CUDA_VISIBLE_DEVICES"] = "-1"
    os.environ.setdefault("TF_CPP_MIN_LOG_LEVEL", "2")

    smi = collect_nvidia_smi()

    import numpy as np
    import tensorflow as tf
    import keras

    physical_gpus = tf.config.list_physical_devices("GPU")
    device_details = []
    for gpu in physical_gpus:
        try:
            details = tf.config.experimental.get_device_details(gpu)
        except Exception:
            details = {}
        device_details.append(
            {
                "name": gpu.name,
                "compute_capability": ".".join(str(v) for v in details.get("compute_capability", ()))
                or None,
                "device_name": details.get("device_name"),
            }
        )

    if args.device == "gpu" and not physical_gpus:
        raise SystemExit("gpu requested but tensorflow reports no physical GPU")

    rng = np.random.default_rng(args.seed)
    x = rng.standard_normal((args.rows, args.features)).astype("float32")
    labels = rng.integers(0, args.classes, args.rows)
    y = keras.utils.to_categorical(labels, num_classes=args.classes)

    model = build_model(args.features, args.classes, args.seed)
    timer = EpochTimer()

    warmup_start = time.perf_counter()
    model.fit(x[: args.batch_size * 4], y[: args.batch_size * 4], epochs=1, batch_size=args.batch_size, verbose=0)
    warmup_seconds = time.perf_counter() - warmup_start

    total_start = time.perf_counter()
    model.fit(
        x,
        y,
        epochs=args.epochs,
        batch_size=args.batch_size,
        verbose=0,
        callbacks=[timer.make_callback()],
    )
    total_seconds = time.perf_counter() - total_start

    steady = timer.times[1:] if len(timer.times) > 1 else timer.times
    report = {
        "device_requested": args.device,
        "seed": args.seed,
        "timestamp_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "platform": platform.platform(),
        "python_version": platform.python_version(),
        "tensorflow_version": tf.__version__,
        "keras_version": keras.__version__,
        "tensorflow_sees_gpu": len(physical_gpus) > 0,
        "gpu_devices": device_details,
        "nvidia_smi": smi,
        "workload": {
            "rows": args.rows,
            "features": args.features,
            "classes": args.classes,
            "epochs": args.epochs,
            "batch_size": args.batch_size,
            "steps_per_epoch": args.rows // args.batch_size,
            "model_parameters": int(model.count_params()),
        },
        "warmup_seconds": round(warmup_seconds, 4),
        "total_seconds": round(total_seconds, 4),
        "epoch_seconds": [round(value, 4) for value in timer.times],
        "mean_epoch_seconds": round(sum(timer.times) / len(timer.times), 4),
        "mean_steady_epoch_seconds": round(sum(steady) / len(steady), 4),
        "min_epoch_seconds": round(min(timer.times), 4),
    }

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"wrote {args.output}")

    print(f"device requested       : {args.device}")
    print(f"tensorflow sees gpu    : {report['tensorflow_sees_gpu']}")
    for entry in device_details:
        print(f"  {entry['device_name']} compute capability {entry['compute_capability']}")
    if smi:
        print(f"nvidia-smi             : {smi['name']}, {smi['memory_total']} total, cc {smi['compute_cap']}")
    print(f"steps per epoch        : {report['workload']['steps_per_epoch']}")
    print(f"model parameters       : {report['workload']['model_parameters']}")
    print(f"warmup seconds         : {report['warmup_seconds']}")
    print(f"total seconds          : {report['total_seconds']}")
    print(f"mean epoch seconds     : {report['mean_epoch_seconds']}")
    print(f"mean steady epoch      : {report['mean_steady_epoch_seconds']}")


if __name__ == "__main__":
    main()
