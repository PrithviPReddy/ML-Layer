import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd

RAW_PARTITION_FILES = [
    "UNSW-NB15_1.csv",
    "UNSW-NB15_2.csv",
    "UNSW-NB15_3.csv",
    "UNSW-NB15_4.csv",
]
OFFICIAL_SPLIT_FILES = [
    "UNSW_NB15_training-set.csv",
    "UNSW_NB15_testing-set.csv",
]
FEATURE_SCHEMA_FILE = "NUSW-NB15_features.csv"
EVENT_LIST_FILE = "UNSW-NB15_LIST_EVENTS.csv"

CHUNK_ROWS = 200_000


def sha256_of_file(path, block_size=1 << 20):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(block_size), b""):
            digest.update(block)
    return digest.hexdigest()


def load_raw_column_names(data_dir):
    schema_path = data_dir / FEATURE_SCHEMA_FILE
    schema = pd.read_csv(schema_path, encoding="cp1252")
    return [str(name) for name in schema["Name"].tolist()]


def profile_raw_partition(path, column_names):
    total_rows = 0
    field_counts = set()
    attack_counts = {}
    label_counts = {}
    stime_min = None
    stime_max = None

    reader = pd.read_csv(
        path,
        header=None,
        names=column_names,
        chunksize=CHUNK_ROWS,
        low_memory=False,
    )
    for chunk in reader:
        total_rows += len(chunk)
        field_counts.add(chunk.shape[1])

        categories = chunk["attack_cat"].fillna("__missing__")
        categories = categories.apply(
            lambda value: "__missing__" if str(value).strip() == "" else str(value).strip().lower()
        )
        for name, count in categories.value_counts().items():
            attack_counts[name] = attack_counts.get(name, 0) + int(count)

        for name, count in chunk["Label"].value_counts().items():
            label_counts[str(name)] = label_counts.get(str(name), 0) + int(count)

        stime = pd.to_numeric(chunk["Stime"], errors="coerce").dropna()
        if len(stime) > 0:
            chunk_min = float(stime.min())
            chunk_max = float(stime.max())
            stime_min = chunk_min if stime_min is None else min(stime_min, chunk_min)
            stime_max = chunk_max if stime_max is None else max(stime_max, chunk_max)

    return {
        "file": path.name,
        "bytes": path.stat().st_size,
        "sha256": sha256_of_file(path),
        "rows": total_rows,
        "columns": sorted(field_counts),
        "has_header_row": False,
        "attack_cat_distribution": dict(sorted(attack_counts.items(), key=lambda kv: -kv[1])),
        "label_distribution": dict(sorted(label_counts.items())),
        "stime_epoch_min": stime_min,
        "stime_epoch_max": stime_max,
        "stime_utc_min": iso_from_epoch(stime_min),
        "stime_utc_max": iso_from_epoch(stime_max),
    }


def iso_from_epoch(value):
    if value is None:
        return None
    return datetime.fromtimestamp(value, timezone.utc).isoformat().replace("+00:00", "Z")


def profile_official_split(path):
    frame = pd.read_csv(path, low_memory=False)
    categories = frame["attack_cat"].fillna("__missing__").astype(str).str.strip().str.lower()
    return {
        "file": path.name,
        "bytes": path.stat().st_size,
        "sha256": sha256_of_file(path),
        "rows": int(len(frame)),
        "columns": int(frame.shape[1]),
        "has_header_row": True,
        "column_names": [str(name) for name in frame.columns.tolist()],
        "attack_cat_distribution": {
            str(name): int(count) for name, count in categories.value_counts().items()
        },
        "label_distribution": {
            str(name): int(count) for name, count in frame["label"].value_counts().items()
        },
    }


def build_manifest(data_dir, seed):
    missing = [
        name
        for name in RAW_PARTITION_FILES + OFFICIAL_SPLIT_FILES + [FEATURE_SCHEMA_FILE]
        if not (data_dir / name).exists()
    ]
    if missing:
        raise FileNotFoundError(f"missing expected dataset files in {data_dir}: {missing}")

    raw_column_names = load_raw_column_names(data_dir)

    raw_profiles = [
        profile_raw_partition(data_dir / name, raw_column_names) for name in RAW_PARTITION_FILES
    ]
    official_profiles = [
        profile_official_split(data_dir / name) for name in OFFICIAL_SPLIT_FILES
    ]

    raw_total_rows = sum(profile["rows"] for profile in raw_profiles)
    raw_combined_attack = {}
    for profile in raw_profiles:
        for name, count in profile["attack_cat_distribution"].items():
            raw_combined_attack[name] = raw_combined_attack.get(name, 0) + count

    official_by_rows = {profile["file"]: profile["rows"] for profile in official_profiles}
    larger_official = max(official_by_rows, key=official_by_rows.get)
    smaller_official = min(official_by_rows, key=official_by_rows.get)
    naming_is_inverted = larger_official == "UNSW_NB15_testing-set.csv"

    stime_min = min(p["stime_epoch_min"] for p in raw_profiles if p["stime_epoch_min"] is not None)
    stime_max = max(p["stime_epoch_max"] for p in raw_profiles if p["stime_epoch_max"] is not None)

    return {
        "generated_at_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "seed": seed,
        "data_dir": str(data_dir.resolve()),
        "python_version": sys.version.split()[0],
        "pandas_version": pd.__version__,
        "variants_present": {
            "raw_four_partition": True,
            "official_pre_split": True,
        },
        "raw_four_partition": {
            "files": raw_profiles,
            "total_rows": raw_total_rows,
            "column_count": len(raw_column_names),
            "column_names": raw_column_names,
            "combined_attack_cat_distribution": dict(
                sorted(raw_combined_attack.items(), key=lambda kv: -kv[1])
            ),
            "stime_epoch_min": stime_min,
            "stime_epoch_max": stime_max,
            "stime_utc_min": iso_from_epoch(stime_min),
            "stime_utc_max": iso_from_epoch(stime_max),
        },
        "official_pre_split": {
            "files": official_profiles,
            "total_rows": sum(profile["rows"] for profile in official_profiles),
            "larger_file_by_rows": larger_official,
            "smaller_file_by_rows": smaller_official,
            "filename_role_inverted": naming_is_inverted,
        },
        "auxiliary_files": {
            FEATURE_SCHEMA_FILE: {
                "bytes": (data_dir / FEATURE_SCHEMA_FILE).stat().st_size,
                "sha256": sha256_of_file(data_dir / FEATURE_SCHEMA_FILE),
            },
            EVENT_LIST_FILE: {
                "bytes": (data_dir / EVENT_LIST_FILE).stat().st_size,
                "sha256": sha256_of_file(data_dir / EVENT_LIST_FILE),
            }
            if (data_dir / EVENT_LIST_FILE).exists()
            else None,
        },
        "schema_compatibility": {
            "raw_and_official_share_schema": False,
            "note": (
                "The raw four-partition files carry 49 unheadered columns named by "
                "NUSW-NB15_features.csv. The official pre-split files carry 45 headed "
                "columns with different names for the same quantities, for example "
                "Spkts against spkts, Sintpkt against sinpkt, smeansz against smean and "
                "res_bdy_len against response_body_len. A model trained on one variant "
                "cannot consume the other without an explicit column mapping."
            ),
        },
    }


def main():
    parser = argparse.ArgumentParser(description="Inventory the UNSW-NB15 dataset on disk.")
    parser.add_argument("--data-dir", type=Path, default=Path(__file__).resolve().parents[1] / "data")
    parser.add_argument(
        "--output",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "results" / "dataset_manifest.json",
    )
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    manifest = build_manifest(args.data_dir, args.seed)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    raw = manifest["raw_four_partition"]
    official = manifest["official_pre_split"]
    print(f"wrote {args.output}")
    print(f"raw four-partition rows: {raw['total_rows']}")
    print(f"raw columns: {raw['column_count']}")
    print(f"raw Stime span: {raw['stime_utc_min']} to {raw['stime_utc_max']}")
    for profile in official["files"]:
        print(f"official {profile['file']}: {profile['rows']} rows, {profile['columns']} columns")
    print(f"filename role inverted: {official['filename_role_inverted']}")


if __name__ == "__main__":
    main()
