"""
Module: Enigma-ML-Layer/level4_verify_abstention.py

Proves the Level 4 done check item: a rejected record reaches the reasoner
carrying abstained set true.

The Level 3 smoke test replays records from the head of the test file, and those
happen to be classified confidently, so it exercises the abstention path zero
times. This script instead scores the whole sampled partition, measures how often
the policy actually fires, then forwards genuinely abstained records over the
real websocket path and reads back what the reasoner recorded.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import subprocess
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

from level3_pipeline import TARGET_COLUMN
from scoring import (
    ABSTENTION_SIGNAL_TYPE,
    decide_abstention,
    resolve_normal_class_index,
    score_prediction,
)
from train_level3 import TEST_FILENAME

HEALTH_TIMEOUT_SECONDS = 90


def load_members(artifacts_dir: Path, config: str, seeds: list[int]) -> list[dict]:
    """Load every ensemble member."""
    from tensorflow.keras.models import load_model

    members = []
    for seed in seeds:
        state = joblib.load(artifacts_dir / f"pipeline_{config}_seed{seed}.pkl")
        members.append(
            {
                "seed": seed,
                "model": load_model(artifacts_dir / f"model_{config}_seed{seed}.keras"),
                "pipeline": state["pipeline"],
                "label_encoder": state["label_encoder"],
            }
        )
    return members


def ensemble_probabilities(members: list[dict], frame: pd.DataFrame) -> np.ndarray:
    """Average every member's prediction over the same raw frame."""
    stacked = np.stack(
        [member["model"].predict(member["pipeline"][:-1].transform(frame), verbose=0) for member in members]
    )
    return stacked.mean(axis=0)


def build_payload(record: dict, scores: dict, abstention: dict, signal_type: str) -> dict:
    """Build the exact envelope main.py emits for one record."""
    return {
        "inputs_for_xai_model": {
            "signal_id": str(uuid.uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "signal_type": signal_type,
            "entity": {
                "device": f"synthetic-device-{int(record.get('id', 0)) % 16:02d}",
                "user": "network_admin",
                "location": "server_rack_1",
            },
            "abstained": abstention["abstained"],
            "calibrated_confidence": abstention["calibrated_confidence"],
            "anomaly_score": scores["anomaly_score"],
            "predicted_class_confidence": scores["predicted_class_confidence"],
            "predictive_entropy": scores["predictive_entropy"],
            "features": ["dur", "sbytes", "dbytes"],
            "source": "unsw-threat-detector",
        }
    }


def wait_for_health(url: str, timeout: int) -> bool:
    """Poll a health endpoint until it answers."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=3) as response:
                if response.status == 200:
                    return True
        except (urllib.error.URLError, OSError):
            time.sleep(1)
    return False


async def send_payloads(uri: str, payloads: list[dict]) -> int:
    """Send payloads to the reasoning layer's signal endpoint."""
    import websockets

    accepted = 0
    async with websockets.connect(uri) as socket:
        for payload in payloads:
            await socket.send(json.dumps(payload))
            response = json.loads(await socket.recv())
            if response.get("status") == "accepted":
                accepted += 1
    return accepted


def main() -> None:
    """Measure the abstention rate and prove abstentions reach the reasoner."""
    parser = argparse.ArgumentParser(description="Verify the Level 4 abstention path.")
    parser.add_argument("--data-dir", type=Path, default=Path("/mnt/f/XAI Project/data"))
    parser.add_argument(
        "--artifacts-dir",
        type=Path,
        default=Path("/mnt/f/XAI Project/artifacts/sensitivity_minimal"),
    )
    parser.add_argument(
        "--agent-dir", type=Path, default=Path("/mnt/f/XAI Project/Enigma-AIAgent")
    )
    parser.add_argument(
        "--agent-python", type=Path, default=Path("/opt/enigma/.venv-agent/bin/python")
    )
    parser.add_argument("--config", type=str, default="openset")
    parser.add_argument("--seeds", type=int, nargs="*", default=[42, 123, 456, 789, 1024])
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--sample", type=int, default=4000)
    parser.add_argument("--forward", type=int, default=20)
    parser.add_argument("--agent-port", type=int, default=8321)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("/mnt/f/XAI Project/results/calibration/abstention_endtoend.json"),
    )
    args = parser.parse_args()

    policy = json.loads(
        (args.artifacts_dir / f"abstention_policy_{args.config}.json").read_text(encoding="utf-8")
    )
    members = load_members(args.artifacts_dir, args.config, args.seeds)
    class_names = [str(name) for name in members[0]["label_encoder"].classes_]
    normal_index = resolve_normal_class_index(class_names)

    test = pd.read_csv(args.data_dir / TEST_FILENAME, low_memory=False)
    sample = test.sample(n=min(args.sample, len(test)), random_state=args.seed).reset_index(drop=True)

    probabilities = ensemble_probabilities(members, sample)
    decisions = [
        decide_abstention(row, policy["temperature"], policy["confidence_threshold"])
        for row in probabilities
    ]
    scores = [score_prediction(row, normal_index) for row in probabilities]
    abstained_flags = np.array([entry["abstained"] for entry in decisions])

    holdout_mask = ~sample[TARGET_COLUMN].isin(class_names).to_numpy()
    measurement = {
        "sample_size": int(len(sample)),
        "abstained_count": int(abstained_flags.sum()),
        "abstention_rate": float(abstained_flags.mean()),
        "confidence_threshold": policy["confidence_threshold"],
        "temperature": policy["temperature"],
        "abstention_rate_on_known": float(abstained_flags[~holdout_mask].mean()),
        "abstention_rate_on_holdout": (
            float(abstained_flags[holdout_mask].mean()) if holdout_mask.any() else None
        ),
        "holdout_in_sample": int(holdout_mask.sum()),
    }

    abstained_indices = np.flatnonzero(abstained_flags)[: args.forward]
    payloads = [
        build_payload(
            sample.iloc[int(index)].to_dict(),
            scores[int(index)],
            decisions[int(index)],
            ABSTENTION_SIGNAL_TYPE,
        )
        for index in abstained_indices
    ]

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

    delivery: dict = {"payloads_sent": len(payloads)}
    try:
        health_url = f"http://127.0.0.1:{args.agent_port}/health"
        delivery["health_reached"] = wait_for_health(health_url, HEALTH_TIMEOUT_SECONDS)
        if delivery["health_reached"] and payloads:
            delivery["accepted"] = asyncio.run(
                send_payloads(f"ws://127.0.0.1:{args.agent_port}/ws/signal", payloads)
            )
            time.sleep(2)
            with urllib.request.urlopen(
                f"http://127.0.0.1:{args.agent_port}/api/situations", timeout=10
            ) as response:
                situations = json.loads(response.read().decode("utf-8"))
            delivery["situation_count"] = situations.get("count", 0)
            delivery["total_evidence"] = sum(
                item["evidence_count"] for item in situations["situations"]
            )
            delivery["abstained_evidence_total"] = sum(
                item.get("abstained_evidence_count", 0) for item in situations["situations"]
            )
            delivery["signal_types_seen"] = sorted(
                {
                    signal_type
                    for item in situations["situations"]
                    for signal_type in item.get("signal_types", [])
                }
            )
            delivery["sample_situation"] = situations["situations"][0]
    finally:
        agent.terminate()
        try:
            agent.wait(timeout=10)
        except subprocess.TimeoutExpired:
            agent.kill()

    report = {
        "seed": args.seed,
        "generated_at_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "config": args.config,
        "ensemble_seeds": args.seeds,
        "measurement": measurement,
        "delivery": delivery,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2), encoding="utf-8")

    print(f"wrote {args.output}")
    print()
    print("=== abstention rate measured on the test partition ===")
    for key, value in measurement.items():
        print(f"  {key}: {value}")
    print()
    print("=== abstained records delivered to the reasoner ===")
    for key, value in delivery.items():
        if key == "sample_situation":
            continue
        print(f"  {key}: {value}")
    if "sample_situation" in delivery:
        print(f"  sample_situation: {json.dumps(delivery['sample_situation'])}")


if __name__ == "__main__":
    main()
