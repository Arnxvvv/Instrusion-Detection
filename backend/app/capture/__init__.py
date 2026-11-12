"""Live traffic capture: frames -> flows -> the model's 44 features."""
from pathlib import Path

from app.capture.flows import Flow, FlowTable
from app.capture.packets import parse_frame
from app.capture.sources import read_pcap


def flows_from_pcap(path: str | Path, max_packets: int | None = None) -> tuple[list[Flow], dict]:
    """Reads a whole capture file as fast as possible (no pacing) and returns finished flows + counters."""
    table, flows = FlowTable(), []
    packets = used = 0
    for ts, raw in read_pcap(path, max_packets):
        packets += 1
        pkt = parse_frame(raw, ts)
        if pkt is None:
            continue
        used += 1
        flows += table.process(pkt)
    flows += table.flush()
    return flows, {"packets": packets, "tcp_udp_packets": used, "single_packet_flows_ignored": table.dropped_single}
