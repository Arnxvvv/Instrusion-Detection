"""Packets -> flows -> the 44 features the model was trained on.

This re-implements the parts of CICFlowMeter (the tool behind CICIDS2017) that those 44 features use.
Where CICFlowMeter has a quirk the model learned, we copy it on purpose. Each quirk below was checked
against the held-out training data (backend/artifacts/test_data.csv), not guessed:

1. The first packet of a flow is counted TWICE in the "Packet Length" stats (mean/variance/min/max).
2. `act_data_pkt_fwd` does not count the first packet.
3. A TCP flow ends at the first FIN (the FIN is included); later packets of the same connection start a new
   flow. A flow also ends 120 s after it started.
4. Single-packet flows are never written out by CICFlowMeter, so we drop them too (and count them).
5. The flag columns in this dataset are not counts: exactly one of FIN / "PSH" / ACK is 1, decided by the
   flow's FIRST packet (SYN -> "PSH" column, FIN -> FIN, anything else -> ACK).
6. Init_Win_bytes_* are -1 until a packet sets them; the backward one is overwritten by every backward packet.
7. Std/variance are sample statistics (n-1), 0 when there is only one value.
"""
import math

from app.capture.packets import FIN, PSH, SYN, Pkt

FLOW_TIMEOUT_US = 120_000_000  # CICFlowMeter: a flow lives at most 120 s
ACTIVITY_TIMEOUT_US = 5_000_000  # gap that splits "active" and "idle" periods


class Stat:
    """Running count/sum/min/max/mean/std (Welford), the same numbers Apache's SummaryStatistics gives."""

    __slots__ = ("n", "total", "mean", "_m2", "min", "max")

    def __init__(self):
        self.n, self.total, self.mean, self._m2 = 0, 0.0, 0.0, 0.0
        self.min, self.max = math.inf, -math.inf

    def add(self, x: float) -> None:
        self.n += 1
        self.total += x
        delta = x - self.mean
        self.mean += delta / self.n
        self._m2 += delta * (x - self.mean)
        if x < self.min:
            self.min = x
        if x > self.max:
            self.max = x

    @property
    def var(self) -> float:
        return self._m2 / (self.n - 1) if self.n > 1 else 0.0

    @property
    def std(self) -> float:
        return math.sqrt(self.var)

    def lo(self) -> float:
        return self.min if self.n else 0.0

    def hi(self) -> float:
        return self.max if self.n else 0.0


class Flow:
    def __init__(self, pkt: Pkt):
        self.src, self.sport, self.dst, self.dport, self.proto = pkt.src, pkt.sport, pkt.dst, pkt.dport, pkt.proto
        self.start = self.last = pkt.ts
        self.length, self.fwd, self.bwd = Stat(), Stat(), Stat()  # payload sizes
        self.iat, self.fiat, self.biat = Stat(), Stat(), Stat()  # inter-arrival times (µs)
        self.active, self.idle = Stat(), Stat()
        self.fwd_hdr = self.bwd_hdr = 0
        self.fwd_bytes = self.bwd_bytes = 0
        self.f_last = pkt.ts
        self.b_last: int | None = None
        self.first_flags = pkt.flags
        self.init_win_f, self.init_win_b = pkt.win, -1
        self.min_seg = pkt.hdr
        self.act_data = 0
        self.act_start = self.act_end = pkt.ts
        self.ended_by_fin = False
        # first packet: quirk 1 (counted twice in `length`) and it is always forward
        self.length.add(pkt.payload)
        self.length.add(pkt.payload)
        self.fwd.add(pkt.payload)
        self.fwd_hdr = pkt.hdr
        self.fwd_bytes = pkt.payload

    def is_forward(self, pkt: Pkt) -> bool:
        return pkt.sport == self.sport and pkt.src == self.src

    @property
    def packets(self) -> int:
        return self.fwd.n + self.bwd.n

    def add(self, pkt: Pkt) -> None:
        if pkt.ts - self.act_end > ACTIVITY_TIMEOUT_US:  # long gap: close the active period, record idle
            if self.act_end - self.act_start > 0:
                self.active.add(self.act_end - self.act_start)
            self.idle.add(pkt.ts - self.act_end)
            self.act_start = self.act_end = pkt.ts
        else:
            self.act_end = pkt.ts

        self.length.add(pkt.payload)
        if self.is_forward(pkt):
            if pkt.payload >= 1:
                self.act_data += 1
            self.fwd.add(pkt.payload)
            self.fwd_hdr += pkt.hdr
            self.fwd_bytes += pkt.payload
            self.fiat.add(pkt.ts - self.f_last)
            self.f_last = pkt.ts
            self.min_seg = min(self.min_seg, pkt.hdr)
        else:
            self.bwd.add(pkt.payload)
            self.init_win_b = pkt.win  # quirk 6: last backward packet wins
            self.bwd_hdr += pkt.hdr
            self.bwd_bytes += pkt.payload
            if self.b_last is not None:
                self.biat.add(pkt.ts - self.b_last)
            self.b_last = pkt.ts
        self.iat.add(pkt.ts - self.last)
        self.last = pkt.ts
        if pkt.proto == 6 and pkt.flags & FIN:
            self.ended_by_fin = True

    def close(self) -> None:
        if self.act_end - self.act_start > 0:
            self.active.add(self.act_end - self.act_start)

    # ------------------------------------------------------------------ the 44 model features
    def features(self) -> dict[str, float | None]:
        dur = self.last - self.start
        secs = dur / 1e6
        # CICFlowMeter writes Infinity/NaN when duration is 0; None = "unknown", the model service fills it in.
        rate = (lambda x: x / secs) if dur > 0 else (lambda x: None)
        is_tcp = self.proto == 6
        if not is_tcp:
            fin = psh = ack = urg = fwd_psh = 0
        else:  # quirk 5
            fin = psh = ack = urg = 0
            if self.first_flags & SYN:
                psh = 1
            elif self.first_flags & FIN:
                fin = 1
            else:
                ack = 1
                urg = 1 if self.bwd.n else 0
            fwd_psh = 1 if self.first_flags & PSH else 0
        return {
            "Flow Duration": float(dur),
            "Total Fwd Packets": float(self.fwd.n),
            "Total Length of Fwd Packets": self.fwd.total,
            "Fwd Packet Length Max": self.fwd.hi(),
            "Fwd Packet Length Min": self.fwd.lo(),
            "Fwd Packet Length Mean": self.fwd.mean,
            "Bwd Packet Length Max": self.bwd.hi(),
            "Bwd Packet Length Min": self.bwd.lo(),
            "Flow Bytes/s": rate(self.fwd_bytes + self.bwd_bytes),
            "Flow Packets/s": rate(self.packets),
            "Flow IAT Mean": self.iat.mean,
            "Flow IAT Std": self.iat.std,
            "Flow IAT Max": self.iat.hi(),
            "Flow IAT Min": self.iat.lo(),
            "Fwd IAT Mean": self.fiat.mean,
            "Fwd IAT Std": self.fiat.std,
            "Fwd IAT Min": self.fiat.lo(),
            "Bwd IAT Total": self.biat.total,
            "Bwd IAT Mean": self.biat.mean,
            "Bwd IAT Std": self.biat.std,
            "Bwd IAT Max": self.biat.hi(),
            "Bwd IAT Min": self.biat.lo(),
            "Fwd PSH Flags": float(fwd_psh),
            "Fwd Header Length": float(self.fwd_hdr),
            "Bwd Header Length": float(self.bwd_hdr),
            "Bwd Packets/s": rate(self.bwd.n),
            "Min Packet Length": self.length.lo(),
            "Max Packet Length": self.length.hi(),
            "Packet Length Mean": self.length.mean,
            "Packet Length Variance": self.length.var,
            "FIN Flag Count": float(fin),
            "PSH Flag Count": float(psh),
            "ACK Flag Count": float(ack),
            "URG Flag Count": float(urg),
            "Down/Up Ratio": float(self.bwd.n // self.fwd.n),
            "Init_Win_bytes_forward": float(self.init_win_f),
            "Init_Win_bytes_backward": float(self.init_win_b),
            "act_data_pkt_fwd": float(self.act_data),
            "min_seg_size_forward": float(self.min_seg),
            "Active Mean": self.active.mean,
            "Active Std": self.active.std,
            "Active Max": self.active.hi(),
            "Active Min": self.active.lo(),
            "Idle Std": self.idle.std,
        }

    def meta(self) -> dict:
        return {
            "src_ip": self.src, "src_port": self.sport, "dst_ip": self.dst, "dst_port": self.dport,
            "proto": "TCP" if self.proto == 6 else "UDP",
            "duration_us": self.last - self.start,
            "fwd_packets": self.fwd.n, "bwd_packets": self.bwd.n,
            "bytes": int(self.fwd_bytes + self.bwd_bytes),
            "ended_by": "fin" if self.ended_by_fin else "timeout",
        }


class FlowTable:
    """Holds the open flows. Not thread-safe on purpose: exactly one thread calls it (see live.py)."""

    def __init__(self, idle_timeout_s: float = 10.0):
        self.flows: dict[tuple, Flow] = {}
        self.idle_us = int(idle_timeout_s * 1e6)
        self.dropped_single = 0  # quirk 4

    def _emit(self, flow: Flow, out: list[Flow]) -> None:
        flow.close()
        if flow.packets > 1:
            out.append(flow)
        else:
            self.dropped_single += 1

    def process(self, pkt: Pkt) -> list[Flow]:
        out: list[Flow] = []
        fwd_key = (pkt.proto, pkt.src, pkt.sport, pkt.dst, pkt.dport)
        key = fwd_key if fwd_key in self.flows else (pkt.proto, pkt.dst, pkt.dport, pkt.src, pkt.sport)
        flow = self.flows.get(key)
        if flow is None:
            self.flows[fwd_key] = Flow(pkt)
            return out
        if pkt.ts - flow.start > FLOW_TIMEOUT_US:  # quirk 3: too old, start over with this packet
            del self.flows[key]
            self._emit(flow, out)
            self.flows[fwd_key] = Flow(pkt)
            return out
        flow.add(pkt)
        if flow.ended_by_fin:  # quirk 3: first FIN ends the flow
            del self.flows[key]
            self._emit(flow, out)
        return out

    def expire(self, now_us: int) -> list[Flow]:
        """Close flows that went quiet (needed for real-time: CICFlowMeter only checks when the next packet comes)."""
        out: list[Flow] = []
        for key, flow in list(self.flows.items()):
            if now_us - flow.last > self.idle_us or now_us - flow.start > FLOW_TIMEOUT_US:
                del self.flows[key]
                self._emit(flow, out)
        return out

    def flush(self) -> list[Flow]:
        out: list[Flow] = []
        for flow in self.flows.values():
            self._emit(flow, out)
        self.flows.clear()
        return out
