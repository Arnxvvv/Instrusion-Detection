# CYBER ATTACK DETECTION SYSTEM — ML-based network attack detection

Open it and it starts working: CYBER ATTACK DETECTION SYSTEM captures traffic, rebuilds connections into *flows*, classifies every flow with your
LightGBM model (CICIDS2017, 7 classes) and pushes the results to a dashboard in real time.

```
network interface ──► packets ──► flow builder ──► LightGBM model ──► WebSocket ──► React dashboard
   (Npcap/libpcap)    (parse)    (44 CICFlowMeter     (your 3 .pkl        (/live/ws)     (served by the
                                  features)            artifacts)                          same server)
```

## Run it (Windows)

1. Install **Python 3.12+** and **Npcap** (https://npcap.com, tick "WinPcap API-compatible mode"). Npcap is only needed for live capture.
2. Right-click `start.bat` → **Run as administrator** (administrator rights let it sniff your network).
   First run creates `.venv` and installs the packages. The browser opens at http://localhost:8000.

Linux/macOS: `sudo ./start.sh`.

No Npcap or no admin rights? It still starts: CYBER ATTACK DETECTION SYSTEM falls back to **Demo flows** (real held-out CICIDS2017 flows
streamed like live traffic) and tells you why in a banner. You can switch source any time on the Monitor page:

| Source | What it watches | Use it for |
|---|---|---|
| Live network | your selected interface, through the real extractor | the real thing |
| Capture file | `data/sample_capture.pcap` (your Wireshark capture) in a loop, through the real extractor | showing the pipeline without admin rights |
| Demo flows | held-out CICIDS2017 test flows, with the true label shown beside each verdict | showing the model catching attacks |

Pages: **Monitor** (live), **Analyze** (upload a .pcap/.pcapng or a CICIDS CSV, or try held-out samples),
**Performance** (metrics, confusion matrix, features).

Developer mode (hot reload): `cd backend && uvicorn app.main:app --reload`, and in another terminal
`cd frontend && npm install && npm run dev` (http://localhost:5173). `npm run build` writes the app into `backend/static`.

## Why it is built this way

* **The model scores flows, not packets.** It was trained on CICFlowMeter's per-connection statistics, so live packets must
  first become the same 44 numbers. That is `backend/app/capture/` (`packets.py` parses frames, `flows.py` builds flows and features).
* **The extractor copies CICFlowMeter's quirks on purpose**, because the model learned them. Each was checked against your held-out
  `test_data.csv` (list at the top of `flows.py`). Example: the first packet of a flow is counted twice in the packet-length
  statistics; the data matches that formula to 1e-8.
* **One thread per job** (`live.py`): sniffing, flow building, scoring and broadcasting never block each other, and the model is
  loaded once at startup and called from one place.
* **One server, one port.** FastAPI serves the built React app, the REST API and the WebSocket.

## What was verified, and what was not

Verified here:
* 35 backend tests pass (`cd backend && pytest`), including parsing, each CICFlowMeter quirk, flow expiry and the live endpoints.
* Your own capture (`naya_capture.pcapng`, 3,058 packets, mostly IPv6) turns into 80 flows and all are classified BENIGN.
* A synthetic connect-scan (SYN → RST/ACK, 1000 ports) built through the extractor is classified PortScan 1000/1000, and synthetic
  normal HTTPS sessions are BENIGN.
* Server, WebSocket push, source switching and pcap upload were run end to end; the pages were rendered and checked in a browser.

Not verified, and you should know:
* **Real live capture could not be tested in my environment** (no Npcap/admin there). The sniffer code path is standard scapy, but
  run it on your machine and check the Monitor page shows packets increasing.
* **Live detection of attack types other than port scans is unproven.** My hand-made imitations of HTTP floods and SSH brute force
  were classified BENIGN, which says my imitations differ from the real CICIDS attacks, not that the model is wrong. The 99.88% accuracy is on
  held-out CICIDS2017 flows (Demo flows / Analyze samples show exactly that).
* **Domain shift is real.** A model trained on a 2017 lab dataset will behave differently on your network. Treat live results as a demo.
  Your own notebook 06 already showed this; the README of `backend/` says the same.
* The flag columns (FIN/PSH/ACK/URG) in this dataset behave as "type of the flow's first packet", not as counts. I derived that rule
  from the data, it is documented in `flows.py` (quirk 5), and it reproduces PortScan correctly, but it is an inference.

## Testing live mode

Run CYBER ATTACK DETECTION SYSTEM as administrator, pick **Live network**, then from *another device you own* (or a VM) scan your PC, or scan that device
from your PC with `python backend/scripts/lab_traffic.py <private-ip-of-your-device>`. The script refuses non-private addresses.
Browse normally and you should see BENIGN flows appear within ~10 seconds (a flow is scored when it ends or goes quiet for 10 s;
change with `CADS_IDLE_TIMEOUT`).

## Settings (environment variables, all optional)

`CADS_SOURCE` auto|live|pcap|demo · `CADS_IFACE` interface id · `CADS_PCAP` capture file ·
`CADS_IDLE_TIMEOUT` seconds · `CADS_AUTOSTART=0` to start idle · `ARTIFACT_DIR` · `CORS_ORIGINS`.

## Folder map

```
backend/app/capture/   packets.py · flows.py · sources.py        live traffic -> 44 features
backend/app/live.py    engine: threads, timeline, websocket hub
backend/app/demo.py    demo stream from held-out flows
backend/app/main.py    REST + WebSocket + serves the React build
backend/artifacts/     model.pkl · scaler.pkl · label_encoder.pkl · metadata.json · test_data.csv
backend/ml/            train_model.py (unchanged: retrain from your dataset)
backend/tests/         35 tests
frontend/src/          React app (Vite)
data/                  sample_capture.pcap · ids_test_sample.csv
```
