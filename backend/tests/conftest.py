"""Test fixtures.

Tests build a tiny throw-away model on synthetic data, so they run in seconds without CICIDS2017.
They check the API logic (ordering, validation, filling, evaluation) - NOT real-world model quality.
"""
import joblib
import numpy as np
import pandas as pd
import pytest
from fastapi.testclient import TestClient
from lightgbm import LGBMClassifier
from sklearn.preprocessing import LabelEncoder, StandardScaler

from app.main import create_app

FEATURES = ["Flow Duration", "Total Fwd Packets", "Flow Bytes/s", "Flow Packets/s", "Init_Win_bytes_forward"]
CLASSES = ["BENIGN", "DDoS", "PortScan"]
CENTERS = {"BENIGN": [1e6, 20, 5e3, 100, 8000], "DDoS": [2e4, 300, 9e5, 5000, 200], "PortScan": [50, 1, 100, 20000, 1000]}


def make_frame(n_per_class: int = 200, seed: int = 0) -> pd.DataFrame:
    rng = np.random.default_rng(seed)
    parts = []
    for label, center in CENTERS.items():
        data = rng.normal(center, np.abs(center) * 0.05, size=(n_per_class, len(FEATURES)))
        part = pd.DataFrame(data, columns=FEATURES)
        part["Label"] = label
        parts.append(part)
    return pd.concat(parts, ignore_index=True)


@pytest.fixture(scope="session")
def artifact_dir(tmp_path_factory):
    folder = tmp_path_factory.mktemp("artifacts")
    df = make_frame()
    encoder = LabelEncoder().fit(df["Label"])
    scaler = StandardScaler().fit(df[FEATURES])
    model = LGBMClassifier(n_estimators=30, random_state=0, verbose=-1)
    model.fit(np.clip(scaler.transform(df[FEATURES]), -10, 10), encoder.transform(df["Label"]))
    joblib.dump(model, folder / "model.pkl")
    joblib.dump(scaler, folder / "scaler.pkl")
    joblib.dump(encoder, folder / "label_encoder.pkl")
    make_frame(20, seed=1).to_csv(folder / "test_data.csv", index=False)
    return folder


@pytest.fixture()
def client(artifact_dir):
    with TestClient(create_app(artifact_dir, autostart=False)) as c:  # `with` runs startup (loads the model)
        yield c


def flow_for(label: str, **overrides) -> dict:
    """A typical flow for a class, in the JSON shape the API expects."""
    features = dict(zip(FEATURES, CENTERS[label]))
    features.update(overrides)
    return {"features": features}
