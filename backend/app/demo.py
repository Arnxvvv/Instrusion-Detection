"""Demo traffic: replays real held-out CICIDS2017 flows (artifacts/test_data.csv) as a live stream.

Used when live capture is not available (or when you pick DEMO in the UI). These are genuine labelled
flows the model never trained on, arranged as calm periods and attack campaigns so the dashboard has something
to show. The addresses are the CICIDS2017 lab topology (the dataset has no IPs in the feature columns), and
every event carries `demo: true` + the `true_label` so the UI can show whether the model got it right.
"""
import random
import threading
import time
from typing import Callable

import pandas as pd

VICTIM, DNS_SERVER, ATTACKER = "192.168.10.50", "192.168.10.3", "172.16.0.1"
CLIENTS = [f"192.168.10.{i}" for i in (5, 8, 9, 12, 14, 15, 16, 17, 19, 25)]
ATTACK_PORTS = {"DDoS": [80], "DoS": [80], "Web Attack": [80], "Brute Force": [21, 22], "Bot": [8080, 443]}


def _meta(label: str, row: dict, rng: random.Random) -> dict:
    dur = row["Flow Duration"]
    fwd = int(row["Total Fwd Packets"])
    total = row["Flow Packets/s"] * dur / 1e6
    udp = row["Init_Win_bytes_forward"] == -1
    if label == "BENIGN":
        src, dst = rng.choice(CLIENTS), rng.choice([VICTIM, DNS_SERVER, "192.168.10.1", "104.18.32.7"])
        port = 53 if udp else rng.choice([443, 443, 80, 8080, 445, 22])
    else:
        src, dst = ATTACKER, VICTIM
        port = rng.randint(1, 1024) if label == "PortScan" else rng.choice(ATTACK_PORTS.get(label, [80]))
    return {
        "src_ip": src, "src_port": rng.randint(1025, 65000), "dst_ip": dst, "dst_port": port,
        "proto": "UDP" if udp else "TCP", "duration_us": int(dur), "fwd_packets": fwd,
        "bwd_packets": max(0, round(total) - fwd), "bytes": int(row["Flow Bytes/s"] * dur / 1e6),
        "ended_by": "demo", "demo": True, "true_label": label,
    }


def run_demo(frame: pd.DataFrame, features: list[str], emit: Callable[[list[dict]], None], stop: threading.Event) -> None:
    rng = random.Random()
    by_label = {lab: grp[features].to_numpy(dtype=float) for lab, grp in frame.groupby("Label")}
    attacks = [lab for lab in by_label if lab != "BENIGN"]
    campaign, phase_end = None, time.monotonic() + 5  # a few calm seconds first, then the first attack
    while not stop.is_set():
        now = time.monotonic()
        if now >= phase_end:
            if campaign is None:
                campaign, phase_end = rng.choice(attacks), now + rng.uniform(7, 12)
            else:
                campaign, phase_end = None, now + rng.uniform(12, 25)
        batch = []
        for _ in range(rng.randint(14, 24) if campaign else rng.randint(2, 6)):
            if campaign and rng.random() < 0.8:
                label = campaign
            else:
                label = rng.choice(attacks) if rng.random() < 0.03 else "BENIGN"
            rows = by_label[label]
            row = dict(zip(features, rows[rng.randrange(len(rows))].tolist()))
            batch.append({"features": row, "meta": _meta(label, row, rng)})
        emit(batch)
        stop.wait(0.5)
