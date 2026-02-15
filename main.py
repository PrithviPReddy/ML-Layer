import asyncio
import json
import time
import uuid
import datetime
import websockets
import pandas as pd
import joblib
from tensorflow.keras.models import load_model
import numpy as np

# --- 1. GLOBALS & CONFIG ---
BATCH_SIZE = 128
TIMEOUT_SECONDS = 0.5
PORT = 8765

# [!] XAI Server Address (Threats go here)
DOWNSTREAM_URI = "ws://13.233.93.2:8000/ws/signal" 

# [!] Normal Traffic Monitor Address (Safe traffic stats go here)
NORMAL_TRAFFIC_URI = "ws://localhost:9000" 

# Global variable for the sockets
frontend_socket = None
downstream_socket = None

# Load model and state
try:
    model = load_model('unsw_nb15_threat_detection_model.h5')
    pipeline_state = joblib.load("unsw_nb15_preprocessing_state.pkl")
    scaler = pipeline_state["scaler"]
    expected_features = pipeline_state["expected_features"]
    columns_to_drop = pipeline_state["dropped_columns"]
    label_encoder = pipeline_state["label_encoder"]
    print("✅ Model and Pipeline State Loaded Successfully.")
except Exception as e:
    print(f"❌ CRITICAL ERROR: Could not load model or pipeline state. {e}")
    exit(1)

# Global async queue
packet_queue = asyncio.Queue()


# --- 2. PREPROCESSING ---
def preprocess_batch(json_packets_list):
    df = pd.DataFrame(json_packets_list)
    
    # Drops based on your notebook logic
    notebook_drops = ['sport', 'dsport', 'proto', 'srcip', 'dstip', 'state', 'service']
    all_drops = set(notebook_drops + columns_to_drop)
    
    existing_drops = [col for col in all_drops if col in df.columns]
    if existing_drops:
        df = df.drop(columns=existing_drops)
        
    # Align features
    for col in expected_features:
        if col not in df.columns:
            df[col] = 0 
    df = df[expected_features]
    
    # Scale
    scaled_data = scaler.transform(df)
    return scaled_data, df  # Return df too so we can grab raw values for JSON


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
    print("Inference worker started...")
    
    # Initialize counters for this session
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
                # 1. Preprocess
                scaled_data, feature_df = await asyncio.to_thread(preprocess_batch, batch)
                
                # 2. Predict
                predictions = await asyncio.to_thread(model.predict, scaled_data, verbose=0)
                
                # 3. Decode Predictions
                predicted_indices = np.argmax(predictions, axis=1)
                attack_names = label_encoder.inverse_transform(predicted_indices)
                
                # 4. ROUTE TRAFFIC
                batch_threat_count = 0
                
                for i, record in enumerate(batch):
                    pred_name = attack_names[i]
                    confidence = float(np.max(predictions[i]))
                    
                    # --- TRAFFIC SPLITTER LOGIC ---
                    
                    if pred_name == 'normal':
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
                        
                        # [FIX] Handle Timestamp safely
                        try:
                            # Try to use the dataset's 'Stime' if it exists
                            ts_val = record.get('Stime', time.time())
                            # Convert to UTC aware datetime
                            dt_object = datetime.datetime.fromtimestamp(int(float(ts_val)), datetime.timezone.utc)
                            iso_timestamp = dt_object.isoformat().replace("+00:00", "Z")
                        except:
                            # Fallback to current time if dataset time fails
                            iso_timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")
                        
                        output_str = f"⚠️ THREAT DETECTED: {pred_name} (Confidence: {confidence:.2f})"

                        payload = {
                            "input_that_i_gave_to_the_model": record,
                            "raw_output_from_model": predictions[i].tolist(),
                            "output_from_model": output_str,
                            "inputs_for_xai_model": {
                                "signal_id": str(uuid.uuid4()),
                                "timestamp": iso_timestamp,
                                "signal_type": pred_name, 
                                "entity": {
                                    "device": record.get("srcip", "unknown_device"), 
                                    "user": "network_admin", 
                                    "location": "server_rack_1" 
                                },
                                "anomaly_score": confidence,
                                "confidence": confidence,
                                "features": list(record.keys()), 
                                "source": "unsw-threat-detector"
                            }
                        }
                        
                        if downstream_socket:
                            await downstream_socket.send(json.dumps(payload))
                
                if batch_threat_count > 0:
                    print(f"⚠️ Batch Processed: {batch_threat_count} Threats Sent | Normal Count is at {session_normal_count}")

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