"""Label cleaning shared by training and serving, copied from notebook 01 so both agree."""

# Keys have two spaces because the raw CSV has a non-ASCII dash that is stripped out.
LABEL_MAP = {
    "Web Attack  Brute Force": "Web Attack",
    "Web Attack  XSS": "Web Attack",
    "Web Attack  Sql Injection": "Web Attack",
    "DoS Hulk": "DoS",
    "DoS GoldenEye": "DoS",
    "DoS slowloris": "DoS",
    "DoS Slowhttptest": "DoS",
    "FTP-Patator": "Brute Force",
    "SSH-Patator": "Brute Force",
}


def clean_label(raw) -> str:
    """Strip whitespace and non-ASCII characters (notebook 01, step 1)."""
    s = str(raw).strip().encode("ascii", "ignore").decode("utf-8")
    return s if s else "UNKNOWN"


def normalize_label(raw) -> str:
    """Clean a raw CICIDS label, then merge it into the 7 training classes."""
    s = clean_label(raw)
    return LABEL_MAP.get(s, s)
