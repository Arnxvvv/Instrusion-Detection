"""Tests for packet parsing, flow building and the live endpoints (no real network or dataset needed)."""
import socket
import struct

import pytest

from app.capture.flows import FlowTable
from app.capture.packets import ACK, FIN, PSH, SYN, Pkt, parse_frame

MAC = b"\x00" * 12


def ipv4_frame(proto: int, l4: bytes, pad_to: int = 0, vlan: bool = False) -> bytes:
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(l4), 0, 0, 64, proto, 0,
                     socket.inet_aton("10.0.0.1"), socket.inet_aton("10.0.0.2"))
    eth = MAC + (b"\x81\x00\x00\x05" if vlan else b"") + b"\x08\x00"
    frame = eth + ip + l4
    return frame + b"\x00" * max(0, pad_to - len(frame))


def tcp_segment(flags: int, payload: int = 0, win: int = 1000, hdr: int = 20) -> bytes:
    offset = (hdr // 4) << 4
    return struct.pack("!HHIIBBHHH", 1234, 80, 0, 0, offset, flags, win, 0, 0) + b"\x01" * (hdr - 20) + b"x" * payload


def pkt(ts, forward=True, flags=ACK, payload=0, hdr=20, win=1000, proto=6):
    a = ("10.0.0.1", 1234, "10.0.0.2", 80)
    s, sp, d, dp = a if forward else (a[2], a[3], a[0], a[1])
    return Pkt(ts, s, d, sp, dp, proto, payload, hdr, flags, win if proto == 6 else -1)


# ------------------------------------------------------------------ parsing
def test_parse_tcp_fields():
    p = parse_frame(ipv4_frame(6, tcp_segment(SYN | ACK, payload=10, win=29200, hdr=32)), 5)
    assert (p.src, p.dst, p.sport, p.dport, p.proto) == ("10.0.0.1", "10.0.0.2", 1234, 80, 6)
    assert (p.payload, p.hdr, p.flags, p.win, p.ts) == (10, 32, SYN | ACK, 29200, 5)


def test_ethernet_padding_counts_as_payload_like_cicflowmeter():
    # a 54-byte ACK padded to 60 bytes by the NIC shows "6 payload bytes" in CICIDS2017
    p = parse_frame(ipv4_frame(6, tcp_segment(ACK), pad_to=60), 0)
    assert p.payload == 6


def test_vlan_tag_is_skipped():
    assert parse_frame(ipv4_frame(6, tcp_segment(ACK, payload=3), vlan=True), 0).payload == 3


def test_udp_uses_cicids_compat_values():
    udp = struct.pack("!HHHH", 5000, 53, 8 + 20, 0) + b"z" * 20
    p = parse_frame(ipv4_frame(17, udp), 0)
    assert (p.proto, p.payload, p.win, p.flags) == (17, 20, -1, 0)


def test_ignored_traffic_returns_none():
    assert parse_frame(ipv4_frame(1, b"\x08\x00" + b"\x00" * 6), 0) is None  # ICMP
    assert parse_frame(b"\x00" * 10, 0) is None  # too short
    assert parse_frame(MAC + b"\x08\x06" + b"\x00" * 28, 0) is None  # ARP


# ------------------------------------------------------------------ flows
def build(packets):
    t = FlowTable()
    flows = []
    for p in packets:
        flows += t.process(p)
    return t, flows + t.flush()


def test_first_packet_counted_twice_in_length_stats():
    # fwd payload 10, bwd payload 40: lengths seen by CICFlowMeter are [10, 10, 40]
    _, flows = build([pkt(0, True, SYN, 10), pkt(100, False, ACK, 40)])
    f = flows[0].features()
    assert f["Packet Length Mean"] == pytest.approx(20.0)
    assert f["Packet Length Variance"] == pytest.approx(300.0)  # sample variance of [10,10,40]
    assert f["Max Packet Length"] == 40 and f["Min Packet Length"] == 10


def test_act_data_pkt_fwd_skips_first_packet():
    _, flows = build([pkt(0, True, ACK, 10), pkt(10, True, ACK, 10), pkt(20, False, ACK, 5)])
    assert flows[0].features()["act_data_pkt_fwd"] == 1.0


def test_single_packet_flows_are_ignored_and_counted():
    t, flows = build([pkt(0)])
    assert flows == [] and t.dropped_single == 1


def test_first_fin_ends_the_flow_and_next_packet_starts_a_new_one():
    t = FlowTable()
    out = []
    for p in [pkt(0, True, SYN), pkt(10, False, SYN | ACK), pkt(20, True, FIN | ACK), pkt(30, False, ACK), pkt(40, True, ACK)]:
        out += t.process(p)
    assert len(out) == 1 and out[0].ended_by_fin and out[0].packets == 3
    assert len(t.flows) == 1  # the leftovers after the FIN form a new flow


def test_flag_columns_follow_the_first_packet():
    _, syn_flow = build([pkt(0, True, SYN), pkt(5, False, ACK)])
    _, ack_flow = build([pkt(0, True, ACK), pkt(5, False, ACK)])
    a, b = syn_flow[0].features(), ack_flow[0].features()
    assert (a["PSH Flag Count"], a["ACK Flag Count"]) == (1.0, 0.0)
    assert (b["PSH Flag Count"], b["ACK Flag Count"]) == (0.0, 1.0)


def test_zero_duration_rates_are_unknown_not_infinite():
    _, flows = build([pkt(100, True, SYN), pkt(100, False, ACK)])
    f = flows[0].features()
    assert f["Flow Bytes/s"] is None and f["Flow Packets/s"] is None


def test_udp_flow_features():
    _, flows = build([pkt(0, True, 0, 30, 20, proto=17), pkt(1000, False, 0, 60, 20, proto=17)])
    f = flows[0].features()
    assert f["Init_Win_bytes_forward"] == -1 and f["Init_Win_bytes_backward"] == -1
    assert f["FIN Flag Count"] == f["ACK Flag Count"] == f["PSH Flag Count"] == 0
    assert f["Down/Up Ratio"] == 1.0


def test_idle_flows_expire():
    t = FlowTable(idle_timeout_s=10)
    t.process(pkt(0, True, SYN))
    t.process(pkt(10, False, ACK))
    assert t.expire(5_000_000) == []
    assert len(t.expire(20_000_000)) == 1


def test_flow_keys_are_bidirectional():
    t = FlowTable()
    t.process(pkt(0, True, SYN))
    t.process(pkt(10, False, ACK))
    assert len(t.flows) == 1


# ------------------------------------------------------------------ live endpoints
def test_live_status_and_snapshot_when_engine_idle(client):
    s = client.get("/live/status").json()
    assert s["mode"] == "idle" and s["running"] is False
    snap = client.get("/live/snapshot").json()
    assert set(snap) == {"status", "stats", "timeline", "events"} and len(snap["timeline"]) == 90


def test_websocket_sends_snapshot_first(client):
    with client.websocket_connect("/live/ws") as ws:
        assert ws.receive_json()["type"] == "snapshot"


def test_bad_source_mode_rejected(client):
    assert client.post("/live/source", json={"mode": "nonsense"}).status_code == 400


def test_pcap_upload_rejects_garbage(client):
    r = client.post("/live/analyze-pcap", files={"file": ("x.pcap", b"this is not a capture")})
    assert r.status_code == 400
