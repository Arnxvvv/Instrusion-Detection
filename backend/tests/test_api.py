import io

import pytest
from fastapi.testclient import TestClient

from app import config
from app.main import create_app
from tests.conftest import CENTERS, FEATURES, flow_for, make_frame


def test_health_and_model_info(client):
    assert client.get("/health").json()["status"] == "ok"
    info = client.get("/model/info").json()
    assert info["features"] == FEATURES  # order comes from the scaler
    assert info["classes"] == ["BENIGN", "DDoS", "PortScan"]


@pytest.mark.parametrize("label", list(CENTERS))
def test_predict_recognises_each_class(client, label):
    r = client.post("/predict", json=flow_for(label))
    assert r.status_code == 200
    body = r.json()
    assert body["label"] == label
    assert body["is_attack"] == (label != "BENIGN")
    assert abs(sum(body["probabilities"].values()) - 1) < 1e-3
    assert (body["severity"] == "none") == (label == "BENIGN")


def test_feature_order_in_request_does_not_matter(client):
    flow = flow_for("DDoS")
    shuffled = {"features": dict(reversed(list(flow["features"].items())))}
    assert client.post("/predict", json=flow).json()["label"] == client.post("/predict", json=shuffled).json()["label"]


def test_missing_feature_is_rejected_with_names(client):
    flow = flow_for("DDoS")
    del flow["features"]["Flow Duration"]
    r = client.post("/predict", json=flow)
    assert r.status_code == 422
    assert r.json()["missing_features"] == ["Flow Duration"]


def test_null_value_is_filled_and_reported(client):
    r = client.post("/predict", json=flow_for("BENIGN", **{"Flow Bytes/s": None}))
    assert r.status_code == 200
    assert r.json()["imputed_values"] == 1


def test_extreme_values_do_not_crash(client):
    r = client.post("/predict", json=flow_for("DDoS", **{"Flow Duration": 1e30}))
    assert r.status_code == 200


def test_meta_is_echoed_back(client):
    flow = flow_for("PortScan")
    flow["meta"] = {"src_ip": "10.0.0.5"}
    assert client.post("/predict", json=flow).json()["meta"] == {"src_ip": "10.0.0.5"}


def test_batch_counts_attacks(client):
    flows = [flow_for("BENIGN"), flow_for("DDoS"), flow_for("PortScan")]
    body = client.post("/predict/batch", json={"flows": flows}).json()
    assert body["count"] == 3 and body["attacks"] == 2
    assert [p["label"] for p in body["predictions"]] == ["BENIGN", "DDoS", "PortScan"]


def test_empty_batch_is_rejected(client):
    assert client.post("/predict/batch", json={"flows": []}).status_code == 422


def test_csv_upload_with_messy_headers_and_labels(client):
    df = make_frame(10, seed=5)
    df.columns = [f" {c}" if c != "Label" else " Label" for c in df.columns]  # CICIDS-style leading spaces
    df.loc[0, " Flow Bytes/s"] = float("inf")
    df.loc[df.index[-1], " Label"] = "Infiltration"  # a class the model never trained on
    buf = io.StringIO()
    df.to_csv(buf, index=False)

    r = client.post("/predict/csv", files={"file": ("test.csv", buf.getvalue(), "text/csv")})
    assert r.status_code == 200
    body = r.json()
    assert body["rows"] == 30
    assert body["rows_with_filled_values"] == 1  # the inf
    ev = body["evaluation"]
    assert ev["skipped_unknown_label_rows"] == 1
    assert ev["accuracy"] > 0.95


def test_csv_without_label_has_no_evaluation(client):
    df = make_frame(5, seed=6).drop(columns="Label")
    r = client.post("/predict/csv", files={"file": ("x.csv", df.to_csv(index=False), "text/csv")})
    assert r.json()["evaluation"] is None


def test_events_and_stats_track_predictions(client):
    client.post("/predict/batch", json={"flows": [flow_for("BENIGN"), flow_for("DDoS")]})
    events = client.get("/events/recent", params={"only_attacks": True}).json()["events"]
    assert [e["label"] for e in events] == ["DDoS"]
    stats = client.get("/stats").json()
    assert stats["total_flows"] == 2 and stats["attack_flows"] == 1


def test_sample_endpoint_returns_sendable_flows(client):
    flows = client.get("/sample", params={"label": "PortScan", "n": 3}).json()["flows"]
    assert len(flows) == 3
    result = client.post("/predict/batch", json={"flows": [{"features": f["features"]} for f in flows]}).json()
    assert all(p["label"] == "PortScan" for p in result["predictions"])


def test_startup_fails_clearly_when_artifacts_missing(tmp_path):
    with pytest.raises(FileNotFoundError, match="model.pkl"):
        with TestClient(create_app(tmp_path, autostart=False)):
            pass


def test_root_serves_the_app_or_redirects_to_docs(client):
    """With the React build present `/` is the dashboard; without it, `/` opens the API docs."""
    r = client.get("/", follow_redirects=False)
    if (config.STATIC_DIR / "index.html").exists():
        assert r.status_code == 200 and "text/html" in r.headers["content-type"]
    else:
        assert r.status_code in (302, 307) and r.headers["location"] == "/docs"