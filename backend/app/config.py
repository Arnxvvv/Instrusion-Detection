"""Central settings. Everything tweakable lives here (or in environment variables)."""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

# Folder that holds model.pkl, scaler.pkl, label_encoder.pkl (+ optional metadata.json, test_data.csv)
ARTIFACT_DIR = Path(os.getenv("ARTIFACT_DIR", BASE_DIR / "artifacts"))

# Must match the preprocessing used in training (notebooks 04/05): StandardScaler, then clip.
CLIP_RANGE = 10.0

BENIGN_LABEL = "BENIGN"

# Limits that protect the server from oversized requests.
MAX_BATCH_FLOWS = 20_000
MAX_CSV_ROWS = 200_000
RECENT_EVENTS_MAX = 1_000  # how many recent predictions /events/recent can return

# React dev server (Vite) is allowed to call this API from the browser.
CORS_ORIGINS = [
    o.strip()
    for o in os.getenv("CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173").split(",")
    if o.strip()
]

# Default severity per predicted class, used by the dashboard for colours/toasts.
# This is a simple editable policy, not something the model learned.
SEVERITY = {
    "BENIGN": "none",
    "PortScan": "medium",
    "Web Attack": "high",
    "Brute Force": "high",
    "DoS": "high",
    "DDoS": "critical",
    "Bot": "critical",
}
DEFAULT_SEVERITY = "high"  # for any attack class not listed above


# ---------------------------------------------------------------------------------------------- live capture
DATA_DIR = BASE_DIR.parent / "data"
STATIC_DIR = Path(os.getenv("STATIC_DIR", BASE_DIR / "static"))  # the built React app (npm run build)

AUTOSTART = os.getenv("CADS_AUTOSTART", "1") != "0"  # start monitoring as soon as the server starts
SOURCE = os.getenv("CADS_SOURCE", "auto")  # auto | live | pcap | demo
IFACE = os.getenv("CADS_IFACE") or None  # None = the interface that reaches the internet
PCAP_PATH = Path(os.getenv("CADS_PCAP", DATA_DIR / "sample_capture.pcap"))
FLOW_IDLE_TIMEOUT_S = float(os.getenv("CADS_IDLE_TIMEOUT", "10"))  # a quiet flow is closed + scored after this
MAX_UPLOAD_PCAP_MB = 50
MAX_UPLOAD_PCAP_PACKETS = 300_000
