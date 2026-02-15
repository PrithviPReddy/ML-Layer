import asyncio
import websockets
import pandas as pd
import json

# --- CONFIGURATION ---
CSV_FILES = [
    "archive/UNSW-NB15_1.csv", 
    "archive/UNSW-NB15_2.csv", 
    "archive/UNSW-NB15_3.csv", 
    "archive/UNSW-NB15_4.csv"
]

# For local testing. Change "localhost" to your EC2 Public IP later!
WS_URI = "ws://localhost:8765" 

BURST_SIZE = 2     # Number of logs to send in a single rapid burst
BURST_DELAY = 0.5    # Pause in seconds between bursts

async def stream_data(websocket):
    """Reads CSVs in chunks and streams them infinitely."""
    # 1. Load the headers first so every JSON packet has the right keys
    features_df = pd.read_csv('archive/NUSW-NB15_features.csv', encoding='cp1252')
    column_names = features_df['Name'].tolist()
    
    loop_count = 1
    while True:
        print(f"\n--- Starting Dataset Loop #{loop_count} ---")
        for file in CSV_FILES:
            print(f"Streaming from {file}...")
            try:
                # 2. ADD header=None and names=column_names HERE
                for chunk in pd.read_csv(file, 
                                        chunksize=BURST_SIZE, 
                                        header=None, 
                                        names=column_names):
                    
                    records = chunk.to_dict(orient='records')
                    for record in records:
                        cleaned_record = {k: (v if pd.notna(v) else "") for k, v in record.items()}
                        await websocket.send(json.dumps(cleaned_record))
                    
                    # Optional: Print a unique value (like 'dur' or 'sbytes') to verify data is changing
                    print(f"Sent burst of {len(records)} logs.")
                    print(records)

                    await asyncio.sleep(BURST_DELAY)
                    
            except FileNotFoundError:
                print(f"ERROR: Could not find {file}. Skipping.")
                await asyncio.sleep(2)
        loop_count += 1

async def main():
    """Manages the connection and automatically reconnects on failure."""
    while True:
        try:
            print(f"Attempting to connect to ML server at {WS_URI}...")
            
            # Establish the WebSocket connection
            async with websockets.connect(WS_URI) as websocket:
                print("Connected! Starting data stream...")
                await stream_data(websocket)
                
        except (websockets.exceptions.ConnectionClosedError, ConnectionRefusedError) as e:
            print(f"Connection lost or refused: {e}")
            print("Retrying in 3 seconds...\n")
            await asyncio.sleep(3)
        except Exception as e:
            print(f"Unexpected error: {e}")
            await asyncio.sleep(3)

if __name__ == "__main__":
    # Start the async event loop
    asyncio.run(main())