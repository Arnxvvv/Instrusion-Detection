"""Trains the final LightGBM model and exports everything the API needs.

Reproduces your notebooks exactly:
  * 01_Create_CICIDS_Subset  -> cleaning, feature filtering, balanced sampling   (only with --raw-dir)
  * 05_CICIDS_Rigorous_Benchmark -> 70/15/15 stratified split (seed 42), StandardScaler fit on train,
                                    clip to [-10, 10], LightGBM(class_weight='balanced')

Usage (run from the backend/ folder):
    python -m ml.train_model --parquet ../Datasets/CICIDS_clean_subset.parquet   # fast: you already have the subset
    python -m ml.train_model --raw-dir ../Datasets/CICIDS                        # from the 8 raw CICIDS CSVs
"""
import argparse
import json
import platform
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import joblib
import lightgbm
import numpy as np
import pandas as pd
import sklearn
from lightgbm import LGBMClassifier
from sklearn.feature_selection import VarianceThreshold
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, f1_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler

from app import config
from app.labels import LABEL_MAP, clean_label

SEED = 42
DROP_COLS = ["Flow ID", "Source IP", "Source Port", "Destination IP", "Timestamp", "Destination Port"]
MIN_SAMPLES = 50
SAMPLE_CAPS = {  # notebook 01, section 4
    "BENIGN": 100_000,
    "DoS": 30_000,
    "DDoS": 25_000,
    "Brute Force": 9_150,
    "Web Attack": 2_143,
    "PortScan": 1_956,
    "Bot": 1_437,
}
LGBM_PARAMS = dict(  # notebook 05
    n_estimators=150, max_depth=8, learning_rate=0.05, class_weight="balanced",
    random_state=SEED, n_jobs=-1, verbose=-1,
)


def build_subset(raw_dir: Path) -> pd.DataFrame:
    """Notebook 01: raw CICIDS day-CSVs -> clean, balanced ~170k-row subset."""
    files = sorted(raw_dir.glob("*.csv"))
    if not files:
        sys.exit(f"No .csv files found in {raw_dir}")
    print(f"Loading {len(files)} CSV files ...")
    df = pd.concat(
        [pd.read_csv(f, encoding_errors="replace", low_memory=False) for f in files], ignore_index=True
    )
    df.columns = df.columns.str.strip()
    df["Label"] = df["Label"].map(clean_label)
    df = df.drop(columns=[c for c in DROP_COLS if c in df.columns])
    df = df.replace([np.inf, -np.inf], np.nan).dropna()
    before = len(df)
    df = df.drop_duplicates()
    print(f"Dropped {before - len(df):,} duplicate rows -> {len(df):,} rows")

    df["Label"] = df["Label"].replace(LABEL_MAP)
    counts = df["Label"].value_counts()
    df = df[df["Label"].isin(counts[counts >= MIN_SAMPLES].index)]
    print("Class counts after merging:\n", df["Label"].value_counts().to_string())

    X, y = df.drop(columns=["Label"]), df["Label"]
    vt = VarianceThreshold(threshold=0.01).fit(X)
    X = X.loc[:, vt.get_support()]
    corr = X.corr().abs()
    upper = corr.where(np.triu(np.ones(corr.shape), k=1).astype(bool))
    X = X.drop(columns=[c for c in upper.columns if (upper[c] > 0.95).any()])
    print(f"Features kept after variance + correlation filter: {X.shape[1]}")

    clean = pd.concat([X, y], axis=1)
    parts = []
    for label, cap in SAMPLE_CAPS.items():
        sub = clean[clean["Label"] == label]
        parts.append(sub.sample(n=cap, random_state=SEED) if len(sub) > cap else sub)
    return pd.concat(parts, ignore_index=True).sample(frac=1, random_state=SEED).reset_index(drop=True)


def train_and_export(df: pd.DataFrame, out_dir: Path) -> None:
    X, y_raw = df.drop(columns=["Label"]), df["Label"]
    encoder = LabelEncoder()
    y = encoder.fit_transform(y_raw)
    classes = [str(c) for c in encoder.classes_]
    print(f"{len(df):,} rows | {X.shape[1]} features | classes: {classes}")

    # Notebook 05: 70% train / 15% validation / 15% test, stratified.
    X_train, X_tmp, y_train, y_tmp = train_test_split(X, y, test_size=0.30, stratify=y, random_state=SEED)
    X_val, X_test, y_val, y_test = train_test_split(X_tmp, y_tmp, test_size=0.50, stratify=y_tmp, random_state=SEED)

    scaler = StandardScaler().fit(X_train)  # fitted on a DataFrame -> remembers feature names/order
    prep = lambda a: np.clip(scaler.transform(a), -config.CLIP_RANGE, config.CLIP_RANGE)

    t0 = time.time()
    model = LGBMClassifier(**LGBM_PARAMS).fit(prep(X_train), y_train)
    train_seconds = time.time() - t0

    pred = model.predict(prep(X_test))
    report = classification_report(y_test, pred, target_names=classes, output_dict=True, zero_division=0)
    metrics = {
        "accuracy": float(accuracy_score(y_test, pred)),
        "macro_f1": float(f1_score(y_test, pred, average="macro", zero_division=0)),
        "weighted_f1": float(f1_score(y_test, pred, average="weighted", zero_division=0)),
        "per_class": report,
        "confusion_matrix": {"labels": classes, "matrix": confusion_matrix(y_test, pred).tolist()},
    }
    print(f"Held-out test -> accuracy {metrics['accuracy']:.4f} | macro F1 {metrics['macro_f1']:.4f}")

    out_dir.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, out_dir / "model.pkl")
    joblib.dump(scaler, out_dir / "scaler.pkl")
    joblib.dump(encoder, out_dir / "label_encoder.pkl")

    # Held-out test rows in RAW (unscaled) units, so the API can be tested exactly like production.
    test_df = X_test.copy()
    test_df["Label"] = encoder.inverse_transform(y_test)
    test_df.to_csv(out_dir / "test_data.csv", index=False)

    metadata = {
        "model_name": "LightGBM (Balanced)",
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "seed": SEED,
        "split": {"train": len(X_train), "validation": len(X_val), "test": len(X_test)},
        "n_features": X.shape[1],
        "classes": classes,
        "hyperparameters": {k: v for k, v in LGBM_PARAMS.items() if k != "n_jobs"},
        "train_seconds": round(train_seconds, 2),
        "test_metrics": metrics,
        "library_versions": {
            "python": platform.python_version(),
            "scikit-learn": sklearn.__version__,
            "lightgbm": lightgbm.__version__,
            "pandas": pd.__version__,
            "numpy": np.__version__,
        },
    }
    (out_dir / "metadata.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    print(f"Saved model.pkl, scaler.pkl, label_encoder.pkl, metadata.json, test_data.csv -> {out_dir}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--parquet", type=Path, help="CICIDS_clean_subset.parquet from notebook 01")
    src.add_argument("--raw-dir", type=Path, help="folder with the raw CICIDS2017 CSV files")
    ap.add_argument("--out", type=Path, default=config.ARTIFACT_DIR, help="where to write the artifacts")
    args = ap.parse_args()

    data = pd.read_parquet(args.parquet) if args.parquet else build_subset(args.raw_dir)
    train_and_export(data, args.out)
