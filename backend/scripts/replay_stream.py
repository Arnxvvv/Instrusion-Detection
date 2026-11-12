"""Streams a CSV through the running API in small batches, like a live traffic feed.

Start the API first (uvicorn app.main:app --port 8000), then:
    python scripts/replay_stream.py artifacts/test_data.csv
    python scripts/replay_stream.py artifacts/test_data.csv --batch 50 --delay 0.5 --max-rows 2000

If the CSV has a Label column, a scoreboard is printed at the end.
This is also the template for real-time use: replace the CSV reading with "flows from a sniffer".
"""
import argparse
import sys
import time
from collections import Counter
from pathlib import Path

import httpx
import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from app.labels import normalize_label  # noqa: E402


def to_json_rows(frame: pd.DataFrame) -> list[dict]:
    """JSON has no NaN/Infinity, so turn them into null (the API fills those in and reports it)."""
    clean = frame.astype(float).replace([np.inf, -np.inf], np.nan).astype(object)
    clean = clean.where(clean.notna(), None)
    return clean.to_dict("records")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("csv", type=Path)
    ap.add_argument("--url", default="http://127.0.0.1:8000")
    ap.add_argument("--batch", type=int, default=100, help="flows per request")
    ap.add_argument("--delay", type=float, default=0.0, help="seconds to wait between batches")
    ap.add_argument("--max-rows", type=int, default=5000)
    args = ap.parse_args()

    with httpx.Client(base_url=args.url, timeout=60) as client:
        info = client.get("/model/info").raise_for_status().json()
        features, known_classes = info["features"], set(info["classes"])

        df = pd.read_csv(args.csv, nrows=args.max_rows, encoding_errors="replace", low_memory=False)
        df.columns = df.columns.str.strip()
        truth = df["Label"].map(normalize_label) if "Label" in df.columns else None

        predicted = Counter()
        correct = total = 0
        for start in range(0, len(df), args.batch):
            chunk = df.iloc[start : start + args.batch]
            rows = to_json_rows(chunk[features])
            payload = {"flows": [{"features": r, "meta": {"row": int(i)}} for r, i in zip(rows, chunk.index)]}
            result = client.post("/predict/batch", json=payload).raise_for_status().json()

            for p in result["predictions"]:
                predicted[p["label"]] += 1
                row = p["meta"]["row"]
                if p["is_attack"]:
                    print(f"[ALERT:{p['severity']:<8}] row {row:>6} -> {p['label']:<11} ({p['confidence']:.1%})")
                if truth is not None and truth.loc[row] in known_classes:  # skip labels never trained on
                    total += 1
                    correct += p["label"] == truth.loc[row]
            if args.delay:
                time.sleep(args.delay)

    print("\nPredicted classes:", dict(predicted))
    if truth is not None and total:
        print(f"Agreement with Label column: {correct}/{total} = {correct / total:.2%}")


if __name__ == "__main__":
    main()
