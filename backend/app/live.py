"""The real-time engine: packet source -> flow table -> model -> events -> every open browser.

Threads (each one has a single job, so no shared mutable state except the queues):

    source thread   LIVE sniffer callback / PCAP replay / DEMO feeder      puts frames or flows on a queue
    pipeline thread parses frames, builds flows, closes quiet ones         puts finished flows on `flow_q`
    scorer thread   batches flows, runs the model, stores + broadcasts     the only place the model is called
    ticker thread   once a second: broadcasts status + counters + timeline

The model is loaded once (ModelService) and shared; nothing here retrains or reloads it.
"""
import asyncio
import collections
import logging
import queue
import threading
import time

import pandas as pd

from app import config
from app.capture.flows import FlowTable
from app.capture.packets import parse_frame
from app.capture.sources import LiveSniffer, default_interface, read_pcap
from app.demo import run_demo
from app.events import EventStore
from app.model_service import ModelService

log = logging.getLogger("cads.live")


class Hub:
    """Fan-out of messages from the engine threads to every connected WebSocket."""

    def __init__(self):
        self._loop: asyncio.AbstractEventLoop | None = None
        self._clients: set[asyncio.Queue] = set()

    def attach(self, loop: asyncio.AbstractEventLoop) -> None:
        self._loop = loop

    def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=300)
        self._clients.add(q)
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        self._clients.discard(q)

    @staticmethod
    def _put(q: asyncio.Queue, msg: dict) -> None:
        if q.full():  # a slow browser must never block the engine: drop its oldest message
            q.get_nowait()
        q.put_nowait(msg)

    def publish(self, msg: dict) -> None:  # called from engine threads
        if self._loop is None or not self._clients:
            return
        for q in list(self._clients):
            self._loop.call_soon_threadsafe(self._put, q, msg)


class Timeline:
    """Flows per second, split into benign / attack, for the live chart."""

    def __init__(self, keep_s: int = 900):
        self._bins: dict[int, list[int]] = collections.defaultdict(lambda: [0, 0])
        self._keep = keep_s
        self._lock = threading.Lock()

    def add(self, events: list[dict]) -> None:
        sec = int(time.time())
        attacks = sum(e["is_attack"] for e in events)
        with self._lock:
            b = self._bins[sec]
            b[0] += len(events) - attacks
            b[1] += attacks
            for old in [s for s in self._bins if s < sec - self._keep]:
                del self._bins[old]

    def series(self, n: int = 90) -> list[dict]:
        now = int(time.time())
        with self._lock:
            return [{"t": s, "benign": self._bins[s][0] if s in self._bins else 0,
                     "attack": self._bins[s][1] if s in self._bins else 0} for s in range(now - n + 1, now + 1)]

    def rate(self, window: int = 5) -> float:
        pts = self.series(window + 1)[:-1]  # skip the still-filling current second
        return round(sum(p["benign"] + p["attack"] for p in pts) / window, 1)


class Engine:
    def __init__(self, service: ModelService, store: EventStore, hub: Hub):
        self.svc, self.store, self.hub = service, store, hub
        self.timeline = Timeline()
        self.flow_q: queue.Queue = queue.Queue(maxsize=50_000)
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []
        self._sniffer: LiveSniffer | None = None
        self._reset("idle")

    # ------------------------------------------------------------------ state
    def _reset(self, mode: str, detail: str = "", error: str | None = None, fallback: bool = False) -> None:
        self.mode, self.detail, self.error, self.fallback = mode, detail, error, fallback
        self.started_at = time.time()
        self.c = {"packets": 0, "tcp_udp": 0, "flows": 0, "single_ignored": 0, "open_flows": 0, "queue_drops": 0}
        self.last_packet_at: float | None = None
        self.score_ms = 0.0

    def status(self) -> dict:
        age = None if self.last_packet_at is None else round(time.time() - self.last_packet_at, 1)
        return {
            "mode": self.mode, "detail": self.detail, "error": self.error, "fallback": self.fallback,
            "running": bool(self._threads) and not self._stop.is_set(),
            "uptime_s": round(time.time() - self.started_at),
            "packets": self.c["packets"], "tcp_udp_packets": self.c["tcp_udp"], "flows_built": self.c["flows"],
            "single_packet_ignored": self.c["single_ignored"], "open_flows": self.c["open_flows"],
            "flows_per_s": self.timeline.rate(), "queue": self.flow_q.qsize(), "score_ms": round(self.score_ms, 1),
            "last_packet_age_s": age,
        }

    def snapshot(self) -> dict:
        return {"status": self.status(), "stats": self.store.stats(), "timeline": self.timeline.series(90),
                "events": self.store.recent(100, False)}

    # ------------------------------------------------------------------ lifecycle
    def start(self, mode: str = "auto", iface: str | None = None) -> dict:
        """Starts (or switches) the traffic source. Returns the new status; `error` explains any fallback."""
        with self._lock:
            self._stop_locked()
            self._stop = threading.Event()
            self._reset("idle")
            stop = self._stop
            self._spawn(self._scorer, stop)
            self._spawn(self._ticker, stop)

            error = None
            if mode in ("auto", "live"):
                try:
                    self._start_live(iface or config.IFACE, stop)
                    return self.status()
                except Exception as exc:  # no Npcap / no permission / wrong interface ...
                    error = str(exc)
                    log.warning("live capture unavailable: %s", error)
            if mode == "pcap":
                try:
                    self._start_pcap(stop)
                    return self.status()
                except Exception as exc:
                    error = str(exc)
            self._start_demo(stop, error=error, fallback=mode in ("auto", "live", "pcap"))
            return self.status()

    def stop(self) -> None:
        with self._lock:
            self._stop_locked()

    def _stop_locked(self) -> None:
        self._stop.set()
        if self._sniffer:
            self._sniffer.stop()
            self._sniffer = None
        for t in self._threads:
            t.join(timeout=2)
        self._threads = []
        while not self.flow_q.empty():
            try:
                self.flow_q.get_nowait()
            except queue.Empty:
                break

    def _spawn(self, target, *args) -> None:
        t = threading.Thread(target=target, args=args, daemon=True, name=target.__name__)
        t.start()
        self._threads.append(t)

    # ------------------------------------------------------------------ sources
    def _start_live(self, iface: str | None, stop: threading.Event) -> None:
        frames: queue.SimpleQueue = queue.SimpleQueue()

        def on_packet(ts: int, raw: bytes) -> None:
            if frames.qsize() < 200_000:  # protects memory if the model can't keep up
                frames.put((ts, raw))

        sniffer = LiveSniffer(iface, on_packet)
        try:
            sniffer.start()  # raises if capture is impossible
        except Exception:
            sniffer.stop()
            raise
        self._sniffer = sniffer
        self._reset("live", f"Interface {sniffer.iface}")
        self._spawn(self._pipeline, frames, lambda: int(time.time() * 1e6), stop)

    def _start_pcap(self, stop: threading.Event) -> None:
        path = config.PCAP_PATH
        if not path.exists():
            raise FileNotFoundError(f"Capture file not found: {path}")
        frames_list = list(read_pcap(path, max_packets=200_000))
        if not frames_list:
            raise ValueError("The capture file has no Ethernet packets.")
        frames: queue.SimpleQueue = queue.SimpleQueue()
        clock = {"ts": frames_list[0][0], "mark": time.monotonic()}

        def now_us() -> int:  # stream time keeps moving between packets so quiet flows can expire
            return int(clock["ts"] + (time.monotonic() - clock["mark"]) * 1e6)

        def replay() -> None:
            base = frames_list[0][0]
            span = frames_list[-1][0] - base + 15_000_000  # gap between loops
            loop = 0
            while not stop.is_set():
                wall0 = time.monotonic()
                for ts, raw in frames_list:
                    wait = (ts - base) / 1e6 - (time.monotonic() - wall0)
                    if wait > 0 and stop.wait(wait):
                        return
                    adjusted = ts + loop * span
                    clock["ts"], clock["mark"] = adjusted, time.monotonic()
                    frames.put((adjusted, raw))
                loop += 1
                stop.wait(0.01)

        self._reset("pcap", f"Replaying {path.name} in a loop")
        self._spawn(replay)
        self._spawn(self._pipeline, frames, now_us, stop)

    def _start_demo(self, stop: threading.Event, error: str | None, fallback: bool) -> None:
        self._reset("demo", "Held-out CICIDS2017 flows replayed as a live stream", error, fallback)
        frame = self.svc.test_frame()
        self._spawn(run_demo, frame, self.svc.features, self._enqueue, stop)

    # ------------------------------------------------------------------ pipeline
    def _enqueue(self, flows: list[dict]) -> None:
        for f in flows:
            try:
                self.flow_q.put_nowait(f)
                self.c["flows"] += 1
            except queue.Full:
                self.c["queue_drops"] += 1

    def _pipeline(self, frames: queue.SimpleQueue, clock, stop: threading.Event) -> None:
        table = FlowTable(config.FLOW_IDLE_TIMEOUT_S)
        last_sweep = time.monotonic()
        while not stop.is_set():
            try:
                ts, raw = frames.get(timeout=0.25)
            except queue.Empty:
                ts = None
            if ts is not None:
                self.c["packets"] += 1
                pkt = parse_frame(raw, ts)
                if pkt is not None:
                    self.c["tcp_udp"] += 1
                    self.last_packet_at = time.time()
                    self._enqueue([{"features": f.features(), "meta": f.meta()} for f in table.process(pkt)])
            if time.monotonic() - last_sweep >= 0.5:
                last_sweep = time.monotonic()
                self._enqueue([{"features": f.features(), "meta": f.meta()} for f in table.expire(clock())])
                self.c["open_flows"], self.c["single_ignored"] = len(table.flows), table.dropped_single

    # ------------------------------------------------------------------ scoring + broadcast
    def _scorer(self, stop: threading.Event) -> None:
        while not stop.is_set():
            try:
                batch = [self.flow_q.get(timeout=0.25)]
            except queue.Empty:
                continue
            while len(batch) < 500:
                try:
                    batch.append(self.flow_q.get_nowait())
                except queue.Empty:
                    break
            try:
                t0 = time.perf_counter()
                results = self.svc.predict(pd.DataFrame([b["features"] for b in batch]), [b["meta"] for b in batch])
                events = self.store.add(results)
                self.score_ms = (time.perf_counter() - t0) * 1000
                self.timeline.add(events)
                self.hub.publish({"type": "flows", "events": events[-200:]})
            except Exception:  # a bad batch must not kill the loop
                log.exception("scoring failed")

    def _ticker(self, stop: threading.Event) -> None:
        while not stop.wait(1.0):
            self.hub.publish({"type": "status", "status": self.status(), "stats": self.store.stats(),
                              "timeline": self.timeline.series(90)})


def probe_default_interface() -> str | None:
    try:
        return default_interface()
    except Exception:
        return None
