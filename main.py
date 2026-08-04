import argparse
import asyncio
import json
import time
import uuid
import datetime
from pathlib import Path

import websockets
import pandas as pd
import joblib
from tensorflow.keras.models import load_model
import numpy as np

from scoring import (
    ABSTENTION_SIGNAL_TYPE,
    decide_abstention,
    resolve_normal_class_index,
    score_prediction,
)

BATCH_SIZE = 128
TIMEOUT_SECONDS = 0.5
PORT = 8765

DOWNSTREAM_URI = "ws://localhost:8000/ws/signal"
NORMAL_TRAFFIC_URI = "ws://localhost:9000"

DEFAULT_ARTIFACTS_DIR = Path(__file__).resolve().parents[1] / "artifacts"
DEFAULT_CONFIG = "closedset"
DEFAULT_MODEL_SEED = 42
DEFAULT_ENSEMBLE_SEEDS = [42, 123, 456, 789, 1024]
ENTITY_POOL_SIZE = 16

frontend_socket = None
downstream_socket = None


def artifact_paths(artifacts_dir, config, seed):
    """Locate the Level 3 model and pipeline for one configuration and seed."""
    return (
        artifacts_dir / f"model_{config}_seed{seed}.keras",
        artifacts_dir / f"pipeline_{config}_seed{seed}.pkl",
    )


def load_ensemble_members(artifacts_dir, config, seeds):
    """Load every ensemble member's model and fitted pipeline.

    The abstention policy is fitted on the ensemble mean, so the serving path
    must run the same ensemble. A single member is measurably sharper than the
    mean, and applying an ensemble-calibrated threshold to a single member
    silently disables the reject option.

    The Level 1 artefacts are deliberately unsupported: they expect the raw 49
    column schema, which the official partition does not use.
    """
    members = []
    for seed in seeds:
        model_path, pipeline_path = artifact_paths(artifacts_dir, config, seed)
        try:
            state = joblib.load(pipeline_path)
            members.append(
                {
                    "seed": seed,
                    "model": load_model(model_path),
                    "pipeline": state["pipeline"],
                    "label_encoder": state["label_encoder"],
                }
            )
        except Exception as exc:
            print(f"Could not load ensemble member seed {seed}: {exc}")
            print(f"Looked for {model_path} and {pipeline_path}")
            print("Run train_level3.py first, or pass --artifacts-dir and --config")
            raise SystemExit(1)

    print(f"Loaded {len(members)} ensemble member(s) for {config}: seeds {seeds}")
    return members


_parser = argparse.ArgumentParser(description="Sensor layer: classify replayed flows and route them.")
_parser.add_argument("--artifacts-dir", type=Path, default=DEFAULT_ARTIFACTS_DIR)
_parser.add_argument("--config", type=str, default=DEFAULT_CONFIG, choices=["closedset", "openset"])
_parser.add_argument("--model-seed", type=int, default=DEFAULT_MODEL_SEED)
_parser.add_argument(
    "--ensemble-seeds",
    type=int,
    nargs="*",
    default=DEFAULT_ENSEMBLE_SEEDS,
    help="Members of the deep ensemble. Must match the seeds the policy was fitted on.",
)
_parser.add_argument("--port", type=int, default=PORT)
_parser.add_argument("--downstream-uri", type=str, default=DOWNSTREAM_URI)
_parser.add_argument("--normal-traffic-uri", type=str, default=NORMAL_TRAFFIC_URI)
_parser.add_argument("--max-records", type=int, default=0)
_parser.add_argument("--no-abstention", action="store_true")
_args = _parser.parse_args()

PORT = _args.port
DOWNSTREAM_URI = _args.downstream_uri
NORMAL_TRAFFIC_URI = _args.normal_traffic_uri

ensemble_members = load_ensemble_members(
    _args.artifacts_dir, _args.config, _args.ensemble_seeds
)
label_encoder = ensemble_members[0]["label_encoder"]
class_names = [str(name) for name in label_encoder.classes_]

normal_class_index = resolve_normal_class_index(class_names)
if normal_class_index is None:
    print("No normal class found in the label encoder, anomaly_score will fall back")
    print(f"Known classes: {class_names}")
else:
    print(f"Normal class index resolved to {normal_class_index} of {class_names}")

def load_abstention_policy(artifacts_dir, config):
    """Load the validation-fitted temperature and rejection threshold.

    Both numbers are produced by run_level4.py from the validation split alone.
    When the artefact is absent the sensor runs without a reject option rather
    than inventing a threshold, and says so.
    """
    path = artifacts_dir / f"abstention_policy_{config}.json"
    if not path.exists():
        print(f"No abstention policy at {path}, running without a reject option")
        return None
    policy = json.loads(path.read_text(encoding="utf-8"))
    print(
        f"Loaded abstention policy: temperature {policy['temperature']:.4f}, "
        f"threshold {policy['confidence_threshold']:.4f}, "
        f"target coverage {policy['target_coverage']:.2f}"
    )
    return policy


abstention_policy = load_abstention_policy(_args.artifacts_dir, _args.config)
if _args.no_abstention:
    abstention_policy = None
    print("Abstention disabled by flag")

records_forwarded = 0
records_abstained = 0
packet_queue = asyncio.Queue()


def resolve_entity_device(record):
    """Derive an entity identifier for a replayed official-partition record.

    The official partition carries no srcip, dstip, sport or dsport column, so
    there is no real entity to correlate on. Without one every signal would
    collapse into a single situation, which would make the reasoning layer
    meaningless rather than merely limited.

    A synthetic device is derived from the flow id so that correlation has
    something to group by during smoke testing. It is synthetic and is labelled
    as such on the wire. Level 7's scenario generator supplies genuine entities.
    """
    flow_id = record.get("id")
    if flow_id is None:
        return "synthetic-device-unknown"
    try:
        return f"synthetic-device-{int(flow_id) % ENTITY_POOL_SIZE:02d}"
    except (TypeError, ValueError):
        return "synthetic-device-unknown"


def resolve_event_timestamp(record):
    """Derive an ISO-8601 UTC timestamp for a replayed record.

    The official partition carries no Stime or Ltime column, only dur and rate,
    so there is no event time to recover and the collector's own clock is used.
    Recorded in paper/EVIDENCE.md appendix L2.2: this is why the Level 8 clock
    study cannot run on the official partition.
    """
    raw = record.get("Stime")
    if raw not in (None, ""):
        try:
            moment = datetime.datetime.fromtimestamp(
                int(float(raw)), datetime.timezone.utc
            )
            return moment.isoformat().replace("+00:00", "Z")
        except (TypeError, ValueError, OSError, OverflowError):
            pass
    return datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")


def predict_batch(json_packets_list):
    """Average every ensemble member's prediction over one batch of records.

    Each member transforms the frame with its own fitted pipeline, because
    mutual information feature selection is seeded and therefore differs between
    members. Slicing the terminal sampler off each pipeline is what guarantees
    SMOTE never runs at inference.

    Returns:
        The ensemble mean probability matrix and the source frame.
    """
    df = pd.DataFrame(json_packets_list)
    member_probabilities = []
    for member in ensemble_members:
        features = member["pipeline"][:-1].transform(df)
        member_probabilities.append(member["model"].predict(features, verbose=0))
    return np.mean(np.stack(member_probabilities), axis=0), df


# --- 3. CONNECTION MANAGERS ---
async def maintain_downstream_connection():
    """Keeps a persistent connection to the XAI server (Threats)."""
    global downstream_socket
    while True:
        try:
            print(f"[Downstream-XAI] Connecting to {DOWNSTREAM_URI}...")
            async with websockets.connect(DOWNSTREAM_URI) as websocket:
                downstream_socket = websocket
                print("[Downstream-XAI] Connected and ready to forward!")
                await websocket.wait_closed()
        except Exception as e:
            print(f"[Downstream-XAI] Connection failed: {e}. Retrying in 5s...")
            downstream_socket = None
            await asyncio.sleep(5)

async def maintain_normal_connection():
    """Keeps a persistent connection to the Normal Traffic Monitor."""
    global frontend_socket
    while True:
        try:
            print(f"[Normal-Stream] Connecting to {NORMAL_TRAFFIC_URI}...")
            async with websockets.connect(NORMAL_TRAFFIC_URI) as websocket:
                frontend_socket = websocket
                print("[Normal-Stream] Connected and ready to forward!")
                await websocket.wait_closed()
        except Exception as e:
            print(f"[Normal-Stream] Connection failed: {e}. Retrying in 5s...")
            frontend_socket = None
            await asyncio.sleep(5)


# --- 4. INFERENCE WORKER (Updated for Python 3.12+) ---
async def inference_worker():
    """Consumes batches, predicts, and routes traffic to TWO different sockets."""
    global records_forwarded, records_abstained
    print("Inference worker started...")

    session_normal_count = 0
    
    while True:
        batch = []
        try:
            # Batch collection logic
            first_packet = await packet_queue.get()
            batch.append(first_packet)
            end_time = time.time() + TIMEOUT_SECONDS
            
            while len(batch) < BATCH_SIZE:
                time_left = end_time - time.time()
                if time_left <= 0: break
                try:
                    packet = await asyncio.wait_for(packet_queue.get(), timeout=time_left)
                    batch.append(packet)
                except asyncio.TimeoutError: break
        except Exception: continue

        if batch:
            try:
                # 1. Preprocess and predict across the ensemble
                predictions, feature_df = await asyncio.to_thread(predict_batch, batch)

                # 3. Decode Predictions
                predicted_indices = np.argmax(predictions, axis=1)
                attack_names = label_encoder.inverse_transform(predicted_indices)
                
                # 4. ROUTE TRAFFIC
                batch_threat_count = 0
                
                for i, record in enumerate(batch):
                    pred_name = attack_names[i]
                    scores = score_prediction(predictions[i], normal_class_index)
                    confidence = scores["predicted_class_confidence"]

                    abstention = None
                    if abstention_policy is not None:
                        abstention = decide_abstention(
                            predictions[i],
                            abstention_policy["temperature"],
                            abstention_policy["confidence_threshold"],
                        )
                        if abstention["abstained"]:
                            records_abstained += 1
                            pred_name = ABSTENTION_SIGNAL_TYPE

                    # --- TRAFFIC SPLITTER LOGIC ---

                    if (
                        abstention is None or not abstention["abstained"]
                    ) and str(pred_name).strip().lower() == 'normal':
                        # A. Handle Normal Traffic
                        session_normal_count += 1
                        
                        # [FIX] Use timezone-aware timestamp
                        current_time = datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")
                        
                        payload_front = {
                            "normal_count": session_normal_count,
                            "timestamp": current_time
                        }
                        
                        if frontend_socket:
                            await frontend_socket.send(json.dumps(payload_front))
                            
                    else:
                        # B. Handle Threat Traffic
                        batch_threat_count += 1
                        
                        iso_timestamp = resolve_event_timestamp(record)

                        output_str = f" THREAT DETECTED: {pred_name} (Confidence: {confidence:.2f})"

                        payload = {
                            "input_that_i_gave_to_the_model": record,
                            "raw_output_from_model": predictions[i].tolist(),
                            "output_from_model": output_str,
                            "inputs_for_xai_model": {
                                "signal_id": str(uuid.uuid4()),
                                "timestamp": iso_timestamp,
                                "signal_type": pred_name,
                                "entity": {
                                    "device": resolve_entity_device(record),
                                    "user": "network_admin",
                                    "location": "server_rack_1"
                                },
                                "abstained": bool(abstention and abstention["abstained"]),
                                "calibrated_confidence": (
                                    abstention["calibrated_confidence"] if abstention else None
                                ),
                                "anomaly_score": scores["anomaly_score"],
                                "predicted_class_confidence": scores["predicted_class_confidence"],
                                "predictive_entropy": scores["predictive_entropy"],
                                "confidence": confidence,
                                "features": list(record.keys()),
                                "source": "unsw-threat-detector"
                            }
                        }
                        
                        if downstream_socket:
                            await downstream_socket.send(json.dumps(payload))
                            records_forwarded += 1
                            if _args.max_records and records_forwarded >= _args.max_records:
                                print(
                                    f"Reached max-records limit of {_args.max_records}, stopping"
                                )
                                raise SystemExit(0)

                if batch_threat_count > 0:
                    print(f" Batch Processed: {batch_threat_count} Threats Sent | Normal Count is at {session_normal_count}")

            except Exception as e:
                print(f"Pipeline error: {e}")


# --- 5. WEBSOCKET HANDLER (The Producer) ---
async def handle_connection(websocket):
    remote_ip = websocket.remote_address[0]
    print(f"Client connected: {remote_ip}")
    async for message in websocket:
        try:
            packet = json.loads(message)
            await packet_queue.put(packet)
        except: pass


# --- 6. MAIN EVENT LOOP ---
async def main():
    # 1. Start Inference Worker
    asyncio.create_task(inference_worker())
    
    # 2. Start Downstream Connection (XAI)
    asyncio.create_task(maintain_downstream_connection())
    
    # 3. Start Normal Connection (Frontend) [ADDED THIS LINE]
    asyncio.create_task(maintain_normal_connection())
    
    # 4. Start Server
    print(f"Starting WebSocket server on ws://0.0.0.0:{PORT}")
    async with websockets.serve(handle_connection, "0.0.0.0", PORT):
        await asyncio.Future()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("Server stopping...")
