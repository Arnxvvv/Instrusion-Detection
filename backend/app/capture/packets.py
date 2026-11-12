"""Turns one raw Ethernet frame into a small `Pkt` tuple (or None if we don't use it).

Why hand-parse instead of using scapy layers? It is ~10x faster, has no hidden magic, and the byte
accounting below must match CICFlowMeter (the tool that produced the CICIDS2017 features):

* payload   = captured frame length - all headers  (so Ethernet padding counts as payload, exactly like
              CICFlowMeter; this is why tiny TCP packets in CICIDS2017 show "6 bytes")
* header    = TCP data-offset * 4
* UDP       = CICIDS2017 reports 20 (not 8) as the "header length" of UDP packets and -1 as the TCP window.
              Every UDP flow in the training set is BENIGN, so we copy those values.
"""
import socket
import struct
from typing import NamedTuple

UDP_HEADER_COMPAT = 20  # what CICIDS2017 stores for UDP (see module docstring)

FIN, SYN, RST, PSH, ACK, URG = 0x01, 0x02, 0x04, 0x08, 0x10, 0x20


class Pkt(NamedTuple):
    ts: int  # capture time, microseconds
    src: str
    dst: str
    sport: int
    dport: int
    proto: int  # 6 = TCP, 17 = UDP
    payload: int  # bytes after the transport header
    hdr: int  # transport header bytes
    flags: int  # TCP flag byte (0 for UDP)
    win: int  # raw TCP window (-1 for UDP)


def parse_frame(raw: bytes, ts: int) -> Pkt | None:
    n = len(raw)
    if n < 14:
        return None
    ethertype = (raw[12] << 8) | raw[13]
    off = 14
    while ethertype in (0x8100, 0x88A8) and n >= off + 4:  # skip VLAN tags
        ethertype = (raw[off + 2] << 8) | raw[off + 3]
        off += 4

    if ethertype == 0x0800:  # IPv4
        if n < off + 20:
            return None
        ihl = (raw[off] & 0x0F) * 4
        if ihl < 20 or n < off + ihl:
            return None
        if ((raw[off + 6] & 0x1F) << 8) | raw[off + 7]:  # non-first fragment: no ports to read
            return None
        proto = raw[off + 9]
        src = socket.inet_ntop(socket.AF_INET, raw[off + 12 : off + 16])
        dst = socket.inet_ntop(socket.AF_INET, raw[off + 16 : off + 20])
        l4 = off + ihl
    elif ethertype == 0x86DD:  # IPv6
        if n < off + 40:
            return None
        proto = raw[off + 6]
        src = socket.inet_ntop(socket.AF_INET6, raw[off + 8 : off + 24])
        dst = socket.inet_ntop(socket.AF_INET6, raw[off + 24 : off + 40])
        l4 = off + 40
        while proto in (0, 43, 60) and n >= l4 + 8:  # hop-by-hop, routing, destination options
            proto, l4 = raw[l4], l4 + (raw[l4 + 1] + 1) * 8
    else:
        return None

    if proto == 6:
        if n < l4 + 20:
            return None
        sport, dport = struct.unpack_from("!HH", raw, l4)
        data_offset = (raw[l4 + 12] >> 4) * 4
        if data_offset < 20:
            return None
        return Pkt(ts, src, dst, sport, dport, 6, max(0, n - l4 - data_offset), data_offset,
                   raw[l4 + 13], (raw[l4 + 14] << 8) | raw[l4 + 15])
    if proto == 17:
        if n < l4 + 8:
            return None
        sport, dport = struct.unpack_from("!HH", raw, l4)
        return Pkt(ts, src, dst, sport, dport, 17, max(0, n - l4 - 8), UDP_HEADER_COMPAT, 0, -1)
    return None  # ICMP etc.: CICFlowMeter ignores them too
