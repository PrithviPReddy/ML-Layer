import asyncio
import websockets
import json
import datetime

# Configuration matching your main.py
HOST = "localhost"
PORT = 9000

async def handle_xai_stream(websocket):
    print(f"\n[Server] Connection established with Main Pipeline!")
    
    try:
        async for message in websocket:
            # 1. Parse the incoming JSON
            payload = json.loads(message)
            
            # 2. Get the timestamp for the log
            # We try to extract it from your custom structure, or just use "now"
            try:
                timestamp = payload["inputs_for_xai_model"]["timestamp"]
            except KeyError:
                timestamp = datetime.datetime.now().isoformat()

            # 3. PRINT THE FULL RAW JSON
            # indent=2 makes it readable (pretty-printed)
            print(f"\n--- [Recv at {timestamp}] ---")
            print(json.dumps(payload, indent=2))
            print("-" * 30)
                
    except websockets.exceptions.ConnectionClosed:
        print("\n[Server] Main Pipeline disconnected.")

async def main():
    print(f"XAI Mock Server listening on ws://{HOST}:{PORT}...")
    async with websockets.serve(handle_xai_stream, HOST, PORT):
        # Keep the server running forever
        await asyncio.Future()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[Server] Stopping...")
