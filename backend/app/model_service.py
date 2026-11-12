"""Loads the trained artifacts once and turns raw flow features into predictions.

The preprocessing here MUST mirror training (notebooks 04/05):
    raw features -> StandardScaler.transform -> clip to [-10, 10] -> model.predict_proba
"""
import json
import threading
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

from app import config
from app.labels import normalize_label

REQUIRED_FILES = ("model.pkl", "scaler.pkl", "label_encoder.pkl")


class MissingFeaturesError(ValueError):
    def __init__(self, missing: list[str]):
        self.missing = missing
        super().__init__(f"{len(missing)} required feature(s) missing")


class ModelService:
    def __init__(self, artifact_dir: Path):
        artifact_dir = Path(artifact_dir)
        absent = [f for f in REQUIRED_FILES if not (artifact_dir / f).exists()]
        if absent:
            raise FileNotFoundError(
                f"Missing {absent} in '{artifact_dir}'. Run `python -m ml.train_model ...` "
                f"or copy your notebook-05 files there (see README)."
            )

        self.artifact_dir = artifact_dir
        self.model = joblib.load(artifact_dir / "model.pkl")
        self.scaler = joblib.load(artifact_dir / "scaler.pkl")
        self.label_encoder = joblib.load(artifact_dir / "label_encoder.pkl")

        # The scaler was fitted on a DataFrame, so it remembers the exact feature names AND order.
        # That list is the single source of truth for what the API expects.
        if not hasattr(self.scaler, "feature_names_in_"):
            raise ValueError("scaler.pkl has no feature_names_in_; it must be fitted on a DataFrame.")
        self.features: list[str] = list(self.scaler.feature_names_in_)
        self.classes: list[str] = [str(c) for c in self.label_encoder.classes_]
        self._fill = pd.Series(self.scaler.mean_, index=self.features)  # value used for missing numbers

        self._validate_consistency()

        self.benign_idx = self.classes.index(config.BENIGN_LABEL) if config.BENIGN_LABEL in self.classes else None
        self.metadata = self._load_json(artifact_dir / "metadata.json")
        self.model_type = type(self.model).__name__
        self._predict_lock = threading.Lock()
        self._test_data: pd.DataFrame | None = None

    # ------------------------------------------------------------------ setup helpers
    def _validate_consistency(self) -> None:
        """Fail at startup (not at the first request) if the three files don't belong together."""
        n_in = getattr(self.model, "n_features_in_", None)
        if n_in is not None and n_in != len(self.features):
            raise ValueError(f"model expects {n_in} features but scaler has {len(self.features)}.")
        model_classes = getattr(self.model, "classes_", None)
        if model_classes is not None and list(model_classes) != list(range(len(self.classes))):
            raise ValueError("model classes do not match label_encoder.pkl.")

    @staticmethod
    def _load_json(path: Path) -> dict:
        return json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}

    # ------------------------------------------------------------------ preprocessing
    def prepare(self, df: pd.DataFrame) -> tuple[np.ndarray, np.ndarray]:
        """Returns (model-ready matrix, number of values that had to be filled in per row)."""
        df = df.rename(columns=lambda c: str(c).strip())  # CICIDS headers have stray spaces
        missing = [f for f in self.features if f not in df.columns]
        if missing:
            raise MissingFeaturesError(missing)

        X = df[self.features].apply(pd.to_numeric, errors="coerce").astype(float)
        X = X.replace([np.inf, -np.inf], np.nan)
        n_filled = X.isna().sum(axis=1).to_numpy()
        # Training dropped rows with inf/NaN, so the model never saw them. For live flows we can't
        # drop a flow, so we substitute the training mean (= 0 after scaling) and report how many.
        X = X.fillna(self._fill)

        scaled = np.clip(self.scaler.transform(X), -config.CLIP_RANGE, config.CLIP_RANGE)
        return scaled, n_filled

    # ------------------------------------------------------------------ prediction
    def predict(self, df: pd.DataFrame, meta: list[dict | None] | None = None) -> list[dict]:
        scaled, n_filled = self.prepare(df)
        with self._predict_lock:
            proba = self.model.predict_proba(scaled)
        top = proba.argmax(axis=1)

        results = []
        for i, row in enumerate(proba):
            label = self.classes[top[i]]
            is_attack = label != config.BENIGN_LABEL
            attack_p = 1.0 - float(row[self.benign_idx]) if self.benign_idx is not None else float(is_attack)
            results.append(
                {
                    "label": label,
                    "confidence": round(float(row[top[i]]), 6),
                    "is_attack": is_attack,
                    "attack_probability": round(attack_p, 6),
                    "severity": config.SEVERITY.get(label, config.DEFAULT_SEVERITY) if is_attack else "none",
                    "probabilities": {c: round(float(p), 6) for c, p in zip(self.classes, row)},
                    "imputed_values": int(n_filled[i]),
                    "meta": meta[i] if meta else None,
                }
            )
        return results

    # ------------------------------------------------------------------ evaluation on labelled data
    def evaluate(self, y_true_raw: pd.Series, predicted: list[str]) -> dict:
        """Compares predictions with true labels (labelled CSV upload)."""
        from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, f1_score

        y_true = y_true_raw.map(normalize_label)
        known = y_true.isin(self.classes).to_numpy()
        y_pred = pd.Series(predicted, index=y_true.index)

        if not known.any():
            return {"evaluated_rows": 0, "skipped_unknown_label_rows": int(len(y_true))}

        yt, yp = y_true[known], y_pred[known]
        labels = self.classes
        return {
            "evaluated_rows": int(known.sum()),
            "skipped_unknown_label_rows": int((~known).sum()),  # e.g. Heartbleed, Infiltration
            "accuracy": round(float(accuracy_score(yt, yp)), 6),
            "macro_f1": round(float(f1_score(yt, yp, labels=labels, average="macro", zero_division=0)), 6),
            "per_class": classification_report(yt, yp, labels=labels, output_dict=True, zero_division=0),
            "confusion_matrix": {"labels": labels, "matrix": confusion_matrix(yt, yp, labels=labels).tolist()},
        }

    # ------------------------------------------------------------------ demo samples
    def test_frame(self) -> pd.DataFrame:
        """The held-out labelled flows (artifacts/test_data.csv), loaded once."""
        if self._test_data is None:
            path = self.artifact_dir / "test_data.csv"
            if not path.exists():
                raise FileNotFoundError("test_data.csv not found (created by ml/train_model.py).")
            df = pd.read_csv(path)
            df.columns = df.columns.str.strip()
            self._test_data = df
        return self._test_data

    def sample_flows(self, label: str | None, n: int) -> list[dict]:
        """Random held-out test rows, shaped exactly like a /predict/batch request."""
        df = self.test_frame()
        if label:
            df = df[df["Label"] == label]
        if df.empty:
            return []
        picked = df.sample(n=min(n, len(df)))
        return [
            {"features": {f: float(row[f]) for f in self.features}, "meta": {"true_label": row["Label"]}}
            for _, row in picked.iterrows()
        ]
