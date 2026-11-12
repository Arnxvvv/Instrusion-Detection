"""In-memory store of recent predictions + running counters (resets when the server restarts)."""
import threading
from collections import Counter, deque
from datetime import datetime, timezone
from itertools import count

from app.config import BENIGN_LABEL


class EventStore:
    def __init__(self, max_events: int):
        self._events = deque(maxlen=max_events)
        self._counts = Counter()
        self._ids = count(1)
        self._lock = threading.Lock()
        self.started_at = datetime.now(timezone.utc)

    def add(self, predictions: list[dict]) -> list[dict]:
        """Stores predictions and returns them as events (with id + timestamp) for live broadcast."""
        now = datetime.now(timezone.utc).isoformat()
        stored = []
        with self._lock:
            for p in predictions:
                self._counts[p["label"]] += 1
                event = {"event_id": next(self._ids), "timestamp": now, **p}
                self._events.append(event)
                stored.append(event)
        return stored

    def recent(self, limit: int, only_attacks: bool) -> list[dict]:
        with self._lock:
            items = list(self._events)
        if only_attacks:
            items = [e for e in items if e["is_attack"]]
        return items[-limit:][::-1]  # newest first

    def stats(self) -> dict:
        with self._lock:
            by_label = dict(self._counts)
        total = sum(by_label.values())
        attacks = total - by_label.get(BENIGN_LABEL, 0)
        return {
            "started_at": self.started_at.isoformat(),
            "total_flows": total,
            "attack_flows": attacks,
            "by_label": by_label,
        }
