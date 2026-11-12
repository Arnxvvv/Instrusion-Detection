"""Request and response shapes. FastAPI validates every request against these automatically."""
from typing import Any

from pydantic import BaseModel, Field

from app.config import MAX_BATCH_FLOWS


class Flow(BaseModel):
    # {"Flow Duration": 1234, ...}. A null value means "unknown" and gets filled in (and reported).
    features: dict[str, float | None]
    # Anything you want echoed back untouched, e.g. {"src_ip": "10.0.0.5", "dst_ip": "10.0.0.9"}.
    # The model never sees it, but alerts need it to be actionable.
    meta: dict[str, Any] | None = None


class BatchRequest(BaseModel):
    flows: list[Flow] = Field(min_length=1, max_length=MAX_BATCH_FLOWS)


class Prediction(BaseModel):
    label: str
    confidence: float
    is_attack: bool
    attack_probability: float
    severity: str
    probabilities: dict[str, float]
    imputed_values: int
    meta: dict[str, Any] | None = None


class BatchResponse(BaseModel):
    count: int
    attacks: int
    latency_ms: float
    predictions: list[Prediction]
