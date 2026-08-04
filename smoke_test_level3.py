"""
Module: Enigma-ML-Layer/smoke_test_level3.py

End to end smoke test for the Level 3 serving path.

Two parts, because they verify different things and fail differently.

Part A scores real test records through the checkpointed model and pipeline and
asserts the D5 semantics hold with the retrained sensor: a record the model
calls Normal must score low on anomaly, and a record it calls an attack must
score high. This is deterministic and needs no network.

Part B starts the reasoning layer and the sensor, replays records over the real
websocket path, and confirms signals arrive and are grouped into situations.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

from level3_pipeline import NORMAL_CLASS, TARGET_COLUMN
from scoring import resolve_normal_class_index, score_prediction

TEST_FILENAME = "UNSW_NB15_training-set.csv"
HEALTH_TIMEOUT_SECONDS = 90
INGEST_TIMEOUT_SECONDS = 120
ANOMALY_LOW_CEILING = 0.1
ANOMALY_HIGH_FLOOR = 0.9


def wait_for_health(url: str, timeout: int) -> bool:
    """Poll a health endpoint until it answers or the timeout expires."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=3) as response:
                if response.status == 200:
                    return True
        except (urllib.error.URLError, OSError):
            time.sleep(1)
    return False


def fetch_json(url: str) -> dict:
    """Fetch and parse a JSON endpoint."""
    with urllib.request.urlopen(url, timeout=10) as response:
        return json.loads(response.read().decode("utf-8"))


def score_real_records(args: argparse.Namespace) -> dict:
    """Part A. Score real test records and check the D5 semantics.

    Args:
        args: Parsed command line arguments.

    Returns:
        A report describing anomaly score behaviour on records the model calls
        Normal against those it calls an attack.
    """
    from tensorflow.keras.models import load_model

    model = load_model(args.artifacts_dir / f"model_{args.config}_seed{args.model_seed}.keras")
    state = joblib.load(
        args.artifacts_dir / f"pipeline_{args.config}_seed{args.model_seed}.pkl"
    )
    pipeline = state["pipeline"]
    label_encoder = state["label_encoder"]
    class_names = [str(name) for name in label_encoder.classes_]
    normal_index = resolve_normal_class_index(class_names)

    test = pd.read_csv(args.data_dir / TEST_FILENAME, low_memory=False)
    sample = test.sample(n=args.records, random_state=args.seed).reset_index(drop=True)

    features = pipeline[:-1].transform(sample)
    probabilities = model.predict(features, verbose=0)

    scored = [score_prediction(row, normal_index) for row in probabilities]
    predicted = [class_names[index] for index in np.argmax(probabilities, axis=1)]

    normal_scores = [
        entry["anomaly_score"]
        for entry, name in zip(scored, predicted)
        if name == NORMAL_CLASS
    ]
    attack_scores = [
        entry["anomaly_score"]
        for entry, name in zip(scored, predicted)
        if name != NORMAL_CLASS
    ]
    class_confidences = [entry["predicted_class_confidence"] for entry in scored]
    entropies = [entry["predictive_entropy"] for entry in scored]

    return {
        "records_scored": int(len(sample)),
        "normal_index": normal_index,
        "class_names": class_names,
        "predicted_normal_count": len(normal_scores),
        "predicted_attack_count": len(attack_scores),
        "anomaly_on_predicted_normal": {
            "mean": float(np.mean(normal_scores)) if normal_scores else None,
            "max": float(np.max(normal_scores)) if normal_scores else None,
        },
        "anomaly_on_predicted_attack": {
            "mean": float(np.mean(attack_scores)) if attack_scores else None,
            "min": float(np.min(attack_scores)) if attack_scores else None,
        },
        "predicted_class_confidence": {
            "mean": float(np.mean(class_confidences)),
            "min": float(np.min(class_confidences)),
        },
        "predictive_entropy": {
            "mean": float(np.mean(entropies)),
            "max": float(np.max(entropies)),
        },
        "all_scores_in_unit_interval": bool(
            all(
                0.0 <= value <= 1.0
                for entry in scored
                for value in entry.values()
            )
        ),
        "normal_below_ceiling": bool(
            not normal_scores or max(normal_scores) < ANOMALY_LOW_CEILING
        ),
        "attack_mean_above_floor": bool(
            not attack_scores or float(np.mean(attack_scores)) > ANOMALY_HIGH_FLOOR
        ),
        "attack_min_above_floor": bool(
            not attack_scores or min(attack_scores) > ANOMALY_HIGH_FLOOR
        ),
        "separation_normal_to_attack": (
            float(np.mean(attack_scores) - np.mean(normal_scores))
            if attack_scores and normal_scores
            else None
        ),
        "anomaly_differs_from_class_confidence": bool(
            any(
                abs(entry["anomaly_score"] - entry["predicted_class_confidence"]) > 0.5
                for entry in scored
            )
        ),
    }


def run_websocket_path(args: argparse.Namespace) -> dict:
    """Part B. Replay records over the real websocket path.

    Args:
        args: Parsed command line arguments.

    Returns:
        A report describing what reached the reasoning layer.
    """
    processes: list[subprocess.Popen] = []
    report: dict = {"started": [], "health_reached": False}

    try:
        agent = subprocess.Popen(
            [
                str(args.agent_python),
                "-m",
                "uvicorn",
                "enigma_reason.main:app",
                "--host",
                "127.0.0.1",
                "--port",
                str(args.agent_port),
                "--log-level",
                "warning",
            ],
            cwd=str(args.agent_dir),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        processes.append(agent)
        report["started"].append("reasoning layer")

        health_url = f"http://127.0.0.1:{args.agent_port}/health"
        report["health_reached"] = wait_for_health(health_url, HEALTH_TIMEOUT_SECONDS)
        if not report["health_reached"]:
            report["error"] = "reasoning layer did not become healthy"
            return report

        sensor = subprocess.Popen(
            [
                sys.executable,
                "main.py",
                "--artifacts-dir",
                str(args.artifacts_dir),
                "--config",
                args.config,
                "--model-seed",
                str(args.model_seed),
                "--port",
                str(args.sensor_port),
                "--downstream-uri",
                f"ws://127.0.0.1:{args.agent_port}/ws/signal",
                "--normal-traffic-uri",
                f"ws://127.0.0.1:{args.sink_port}",
                "--max-records",
                str(args.records),
            ],
            cwd=str(Path(__file__).resolve().parent),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        processes.append(sensor)
        report["started"].append("sensor layer")
        time.sleep(20)

        streamer = subprocess.Popen(
            [
                sys.executable,
                "Streamer.py",
                "--data-dir",
                str(args.data_dir),
                "--uri",
                f"ws://127.0.0.1:{args.sensor_port}",
                "--burst-size",
                "20",
                "--burst-delay",
                "0.05",
            ],
            cwd=str(Path(__file__).resolve().parent),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        processes.append(streamer)
        report["started"].append("replayer")

        deadline = time.time() + INGEST_TIMEOUT_SECONDS
        situations: dict = {"situations": [], "count": 0}
        while time.time() < deadline:
            try:
                situations = fetch_json(
                    f"http://127.0.0.1:{args.agent_port}/api/situations"
                )
                if situations.get("count", 0) > 0:
                    evidence = sum(
                        item["evidence_count"] for item in situations["situations"]
                    )
                    if evidence >= args.min_evidence:
                        break
            except (urllib.error.URLError, OSError, KeyError):
                pass
            time.sleep(2)

        health = fetch_json(health_url)

        total_evidence = sum(
            item["evidence_count"] for item in situations.get("situations", [])
        )
        anomalies = [
            item["max_anomaly"]
            for item in situations.get("situations", [])
            if item.get("max_anomaly") is not None
        ]

        report.update(
            {
                "situation_count": situations.get("count", 0),
                "total_evidence": total_evidence,
                "signal_types_seen": sorted(
                    {
                        signal_type
                        for item in situations.get("situations", [])
                        for signal_type in item.get("signal_types", [])
                    }
                ),
                "entities_seen": sorted(
                    {
                        entity
                        for item in situations.get("situations", [])
                        for entity in item.get("entities", [])
                    }
                )[:8],
                "max_anomaly_range": {
                    "min": float(min(anomalies)) if anomalies else None,
                    "max": float(max(anomalies)) if anomalies else None,
                },
                "abstained_evidence_total": sum(
                    item.get("abstained_evidence_count", 0)
                    for item in situations.get("situations", [])
                ),
                "situations_with_abstention": sum(
                    1
                    for item in situations.get("situations", [])
                    if item.get("abstained_evidence_count", 0) > 0
                ),
                "adapters": health.get("adapters", []),
                "total_adapted": health.get("total_adapted", 0),
                "total_rejected": health.get("total_rejected", 0),
                "sample_situation": (
                    situations["situations"][0] if situations.get("situations") else None
                ),
            }
        )
        return report

    finally:
        for process in reversed(processes):
            process.terminate()
        for process in reversed(processes):
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()


def main() -> None:
    """Run both parts of the smoke test and write the combined report."""
    parser = argparse.ArgumentParser(description="Level 3 end to end smoke test.")
    parser.add_argument("--data-dir", type=Path, default=Path("/mnt/f/XAI Project/data"))
    parser.add_argument(
        "--artifacts-dir", type=Path, default=Path("/mnt/f/XAI Project/artifacts")
    )
    parser.add_argument(
        "--agent-dir", type=Path, default=Path("/mnt/f/XAI Project/Enigma-AIAgent")
    )
    parser.add_argument(
        "--agent-python", type=Path, default=Path("/opt/enigma/.venv-agent/bin/python")
    )
    parser.add_argument("--config", type=str, default="openset")
    parser.add_argument("--model-seed", type=int, default=42)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--records", type=int, default=100)
    parser.add_argument("--min-evidence", type=int, default=25)
    parser.add_argument("--agent-port", type=int, default=8123)
    parser.add_argument("--sensor-port", type=int, default=8765)
    parser.add_argument("--sink-port", type=int, default=9123)
    parser.add_argument("--skip-websocket", action="store_true")
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("/mnt/f/XAI Project/results/classifier/smoke_test.json"),
    )
    args = parser.parse_args()

    scoring_report = score_real_records(args)
    websocket_report = None if args.skip_websocket else run_websocket_path(args)

    report = {
        "seed": args.seed,
        "generated_at_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "config": args.config,
        "model_seed": args.model_seed,
        "part_a_scoring": scoring_report,
        "part_b_websocket": websocket_report,
    }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2), encoding="utf-8")

    print(f"wrote {args.output}")
    print()
    print("=== Part A, scoring real records through the checkpointed sensor ===")
    for key in (
        "records_scored",
        "predicted_normal_count",
        "predicted_attack_count",
        "anomaly_on_predicted_normal",
        "anomaly_on_predicted_attack",
        "normal_below_ceiling",
        "attack_mean_above_floor",
        "attack_min_above_floor",
        "separation_normal_to_attack",
        "all_scores_in_unit_interval",
        "anomaly_differs_from_class_confidence",
    ):
        print(f"  {key}: {scoring_report[key]}")

    if websocket_report is not None:
        print()
        print("=== Part B, full websocket path ===")
        for key in (
            "started",
            "health_reached",
            "situation_count",
            "total_evidence",
            "signal_types_seen",
            "entities_seen",
            "max_anomaly_range",
            "abstained_evidence_total",
            "situations_with_abstention",
            "total_adapted",
            "total_rejected",
        ):
            print(f"  {key}: {websocket_report.get(key)}")


if __name__ == "__main__":
    main()
