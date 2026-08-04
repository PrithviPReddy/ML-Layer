"""
Module: Enigma-ML-Layer/write_split_manifest.py

Records the exact three-way split used by Level 3, independently of any model
run, so the split can be audited without retraining.

Roles are assigned by row count, never by filename. The distributed official
partition has inverted filenames, recorded in paper/EVIDENCE.md appendix L1.3.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
from sklearn.model_selection import train_test_split

from level3_pipeline import CATEGORICAL_COLUMNS, DROPPED_COLUMNS, TARGET_COLUMN, resolve_numeric_columns
from train_level3 import POOL_FILENAME, TEST_FILENAME


def sha256_of_file(path: Path, block_size: int = 1 << 20) -> str:
    """Return the SHA-256 of a file."""
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(block_size), b""):
            digest.update(block)
    return digest.hexdigest()


def distribution(frame: pd.DataFrame) -> dict[str, int]:
    """Class counts sorted by class name."""
    return {
        str(name): int(count)
        for name, count in frame[TARGET_COLUMN].value_counts().sort_index().items()
    }


def main() -> None:
    """Build and write the split manifest."""
    parser = argparse.ArgumentParser(description="Record the Level 3 three-way split.")
    parser.add_argument("--data-dir", type=Path, default=Path("/mnt/f/XAI Project/data"))
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--validation-size", type=float, default=0.2)
    parser.add_argument("--holdout-class", type=str, default="Worms")
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("/mnt/f/XAI Project/results/classifier/split_manifest.json"),
    )
    args = parser.parse_args()

    pool = pd.read_csv(args.data_dir / POOL_FILENAME, low_memory=False)
    test = pd.read_csv(args.data_dir / TEST_FILENAME, low_memory=False)

    train_frame, validation_frame = train_test_split(
        pool,
        test_size=args.validation_size,
        random_state=args.seed,
        stratify=pool[TARGET_COLUMN],
    )

    open_train = train_frame[train_frame[TARGET_COLUMN] != args.holdout_class]
    open_validation = validation_frame[validation_frame[TARGET_COLUMN] != args.holdout_class]

    numeric_columns = resolve_numeric_columns(pool)
    pool_labels = sorted(str(value) for value in pool[TARGET_COLUMN].unique())
    test_labels = sorted(str(value) for value in test[TARGET_COLUMN].unique())
    normalised = sorted({value.strip().lower() for value in pool_labels})

    manifest = {
        "seed": args.seed,
        "generated_at_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "partition_roles": {
            "note": "assigned by row count, the distributed filenames are inverted",
            "pool_file": POOL_FILENAME,
            "pool_rows": int(len(pool)),
            "pool_sha256": sha256_of_file(args.data_dir / POOL_FILENAME),
            "test_file": TEST_FILENAME,
            "test_rows": int(len(test)),
            "test_sha256": sha256_of_file(args.data_dir / TEST_FILENAME),
        },
        "labels": {
            "pool_labels": pool_labels,
            "test_labels": test_labels,
            "label_sets_identical": pool_labels == test_labels,
            "distinct_after_strip_and_lower": normalised,
            "label_artefact_present": len(pool_labels) != len(normalised),
            "backdoor_spelling": [value for value in pool_labels if "ackdoor" in value],
        },
        "columns": {
            "total": int(pool.shape[1]),
            "dropped": DROPPED_COLUMNS,
            "dropped_reason": {
                "id": "row index, carries no signal",
                "label": "perfectly determined by attack_cat, a direct target leak",
            },
            "target": TARGET_COLUMN,
            "categorical": CATEGORICAL_COLUMNS,
            "numeric_candidates": numeric_columns,
            "numeric_candidate_count": len(numeric_columns),
        },
        "closedset": {
            "train_rows": int(len(train_frame)),
            "validation_rows": int(len(validation_frame)),
            "test_rows": int(len(test)),
            "train_distribution": distribution(train_frame),
            "validation_distribution": distribution(validation_frame),
            "test_distribution": distribution(test),
        },
        "openset": {
            "holdout_class": args.holdout_class,
            "train_rows": int(len(open_train)),
            "validation_rows": int(len(open_validation)),
            "test_rows": int(len(test)),
            "holdout_rows_removed_from_train": int(
                len(train_frame) - len(open_train)
            ),
            "holdout_rows_removed_from_validation": int(
                len(validation_frame) - len(open_validation)
            ),
            "holdout_rows_in_test": int((test[TARGET_COLUMN] == args.holdout_class).sum()),
            "train_distribution": distribution(open_train),
            "validation_distribution": distribution(open_validation),
        },
    }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    print(f"wrote {args.output}")
    print(f"pool  {POOL_FILENAME} {len(pool)} rows")
    print(f"test  {TEST_FILENAME} {len(test)} rows")
    print()
    print(f"{'class':<16}{'train':>9}{'val':>9}{'test':>9}")
    for name in sorted(manifest["closedset"]["train_distribution"]):
        print(
            f"{name:<16}"
            f"{manifest['closedset']['train_distribution'].get(name, 0):>9}"
            f"{manifest['closedset']['validation_distribution'].get(name, 0):>9}"
            f"{manifest['closedset']['test_distribution'].get(name, 0):>9}"
        )
    totals = manifest["closedset"]
    print(
        f"{'TOTAL':<16}{totals['train_rows']:>9}"
        f"{totals['validation_rows']:>9}{totals['test_rows']:>9}"
    )
    print()
    print(f"label sets identical : {manifest['labels']['label_sets_identical']}")
    print(f"label artefact       : {manifest['labels']['label_artefact_present']}")
    print(f"backdoor spelling    : {manifest['labels']['backdoor_spelling']}")
    print(f"numeric candidates   : {manifest['columns']['numeric_candidate_count']}")
    print()
    print(f"openset holdout      : {manifest['openset']['holdout_class']}")
    print(f"  removed from train : {manifest['openset']['holdout_rows_removed_from_train']}")
    print(f"  removed from val   : {manifest['openset']['holdout_rows_removed_from_validation']}")
    print(f"  present in test    : {manifest['openset']['holdout_rows_in_test']}")


if __name__ == "__main__":
    main()
