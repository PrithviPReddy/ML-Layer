import argparse
import asyncio
import json
from pathlib import Path

import pandas as pd
import websockets

OFFICIAL_TEST_PARTITION = "UNSW_NB15_training-set.csv"
OFFICIAL_TRAIN_PARTITION = "UNSW_NB15_testing-set.csv"

DEFAULT_DATA_DIR = Path(__file__).resolve().parents[1] / "data"
DEFAULT_WS_URI = "ws://localhost:8765"
DEFAULT_BURST_SIZE = 2
DEFAULT_BURST_DELAY = 0.5


async def stream_data(websocket, data_dir, partition_file, burst_size, burst_delay, verbose):
    """Replay one CSV partition to the sensor layer, looping indefinitely.

    Args:
        websocket: Open connection to the sensor layer.
        data_dir: Directory holding the UNSW-NB15 files.
        partition_file: Filename of the partition to replay.
        burst_size: Records sent per burst.
        burst_delay: Seconds paused between bursts.
        verbose: Print each burst's contents.
    """
    path = data_dir / partition_file
    loop_count = 1
    while True:
        print(f"Starting dataset loop {loop_count} from {path}")
        try:
            for chunk in pd.read_csv(path, chunksize=burst_size, low_memory=False):
                records = chunk.to_dict(orient="records")
                for record in records:
                    cleaned_record = {
                        key: (value if pd.notna(value) else "") for key, value in record.items()
                    }
                    await websocket.send(json.dumps(cleaned_record))

                if verbose:
                    print(f"Sent burst of {len(records)} logs")
                    print(records)

                await asyncio.sleep(burst_delay)

        except FileNotFoundError:
            print(f"Could not find {path}")
            await asyncio.sleep(2)
        loop_count += 1


async def run(args):
    while True:
        try:
            print(f"Connecting to sensor layer at {args.uri}")
            async with websockets.connect(args.uri) as websocket:
                print("Connected, starting data stream")
                await stream_data(
                    websocket,
                    args.data_dir,
                    args.partition_file,
                    args.burst_size,
                    args.burst_delay,
                    args.verbose,
                )

        except (websockets.exceptions.ConnectionClosedError, ConnectionRefusedError) as exc:
            print(f"Connection lost or refused: {exc}")
            print("Retrying in 3 seconds")
            await asyncio.sleep(3)
        except Exception as exc:
            print(f"Unexpected error: {exc}")
            await asyncio.sleep(3)


def main():
    """Parse arguments and run the replayer until interrupted."""
    parser = argparse.ArgumentParser(
        description=(
            "Replay the official UNSW-NB15 test partition to the sensor layer. "
            "The official filenames are inverted in the distributed dataset: the "
            "file named training-set holds 82332 rows and is the test partition, "
            "and the file named testing-set holds 175341 rows and is the train "
            "partition. See paper/EVIDENCE.md appendix L1.3."
        )
    )
    parser.add_argument("--data-dir", type=Path, default=DEFAULT_DATA_DIR)
    parser.add_argument(
        "--partition-file",
        type=str,
        default=OFFICIAL_TEST_PARTITION,
        help=(
            f"Partition to replay. Defaults to {OFFICIAL_TEST_PARTITION}, which "
            f"is the 82332 row test partition. The train partition is "
            f"{OFFICIAL_TRAIN_PARTITION}."
        ),
    )
    parser.add_argument("--uri", type=str, default=DEFAULT_WS_URI)
    parser.add_argument("--burst-size", type=int, default=DEFAULT_BURST_SIZE)
    parser.add_argument("--burst-delay", type=float, default=DEFAULT_BURST_DELAY)
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    if not args.data_dir.exists():
        raise SystemExit(f"data directory not found: {args.data_dir}")
    if not (args.data_dir / args.partition_file).exists():
        raise SystemExit(f"partition not found: {args.data_dir / args.partition_file}")

    asyncio.run(run(args))


if __name__ == "__main__":
    main()