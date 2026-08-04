import argparse
import json
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd

PARTITION_FILES = [
    "UNSW-NB15_1.csv",
    "UNSW-NB15_2.csv",
    "UNSW-NB15_3.csv",
    "UNSW-NB15_4.csv",
]
FEATURE_SCHEMA_FILE = "NUSW-NB15_features.csv"


def drop_caches():
    try:
        subprocess.run(["sync"], check=False, timeout=30)
        with open("/proc/sys/vm/drop_caches", "w") as handle:
            handle.write("3")
        return True
    except (OSError, PermissionError, FileNotFoundError, subprocess.TimeoutExpired):
        return False


def time_raw_read(data_dir):
    total_bytes = 0
    start = time.perf_counter()
    for name in PARTITION_FILES:
        path = data_dir / name
        with open(path, "rb") as handle:
            while True:
                block = handle.read(1 << 22)
                if not block:
                    break
                total_bytes += len(block)
    elapsed = time.perf_counter() - start
    return elapsed, total_bytes


def time_pandas_read(data_dir):
    schema = pd.read_csv(data_dir / FEATURE_SCHEMA_FILE, encoding="cp1252")
    column_names = [str(name) for name in schema["Name"].tolist()]

    start = time.perf_counter()
    rows = 0
    for name in PARTITION_FILES:
        frame = pd.read_csv(
            data_dir / name, header=None, names=column_names, low_memory=False
        )
        rows += len(frame)
        del frame
    elapsed = time.perf_counter() - start
    return elapsed, rows


def main():
    parser = argparse.ArgumentParser(description="Measure dataset read cost from a given directory.")
    parser.add_argument("--data-dir", type=Path, required=True)
    parser.add_argument("--label", type=str, required=True)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--drop-caches", action="store_true")
    parser.add_argument("--output", type=Path, default=None)
    args = parser.parse_args()

    caches_dropped = drop_caches() if args.drop_caches else False

    raw_seconds, total_bytes = time_raw_read(args.data_dir)
    pandas_seconds, rows = time_pandas_read(args.data_dir)

    report = {
        "label": args.label,
        "seed": args.seed,
        "data_dir": str(args.data_dir),
        "timestamp_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "caches_dropped": caches_dropped,
        "total_bytes": total_bytes,
        "total_megabytes": round(total_bytes / (1 << 20), 1),
        "raw_read_seconds": round(raw_seconds, 3),
        "raw_read_mb_per_second": round((total_bytes / (1 << 20)) / raw_seconds, 1),
        "pandas_read_seconds": round(pandas_seconds, 3),
        "pandas_rows": rows,
    }

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"wrote {args.output}")

    print(f"label                  : {args.label}")
    print(f"data dir               : {args.data_dir}")
    print(f"caches dropped         : {caches_dropped}")
    print(f"bytes                  : {report['total_megabytes']} MB")
    print(f"raw read seconds       : {report['raw_read_seconds']}")
    print(f"raw read MB/s          : {report['raw_read_mb_per_second']}")
    print(f"pandas read seconds    : {report['pandas_read_seconds']}")
    print(f"pandas rows            : {rows}")


if __name__ == "__main__":
    main()
