"""Where raw frames come from: a pcap/pcapng file, or a live network interface.

scapy is only used for I/O (reading files, talking to Npcap/libpcap). All packet understanding is in packets.py.
Live capture needs Npcap (Windows) or libpcap (Linux/macOS) plus permission to sniff (Administrator / root).
"""
import time
from pathlib import Path
from typing import Callable, Iterator

PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"
ETHERNET = 1


def read_pcap(path: str | Path, max_packets: int | None = None) -> Iterator[tuple[int, bytes]]:
    """Yields (timestamp in microseconds, raw Ethernet frame). Works for .pcap and .pcapng."""
    from scapy.utils import RawPcapNgReader, RawPcapReader

    path = Path(path)
    with open(path, "rb") as fh:
        is_ng = fh.read(4) == PCAPNG_MAGIC
    reader = RawPcapNgReader(str(path)) if is_ng else RawPcapReader(str(path))
    count = 0
    try:
        for data, meta in reader:
            if is_ng:
                if meta.linktype != ETHERNET:
                    continue
                ts = ((meta.tshigh << 32) | meta.tslow) * 1_000_000 // meta.tsresol
            else:
                if reader.linktype != ETHERNET:
                    raise ValueError(f"Unsupported capture link type {reader.linktype} (need Ethernet).")
                ts = meta.sec * 1_000_000 + (meta.usec // 1000 if reader.nano else meta.usec)
            yield ts, bytes(data)
            count += 1
            if max_packets and count >= max_packets:
                break
    finally:
        reader.close()


def list_interfaces() -> list[dict]:
    """Network interfaces scapy can see: [{'id','name','ip','default'}]."""
    from scapy.all import conf

    default = default_interface()
    out = []
    for iface in conf.ifaces.values():
        name = getattr(iface, "network_name", None) or iface.name
        desc = getattr(iface, "description", "") or iface.name
        ip = getattr(iface, "ip", "") or ""
        if ip.startswith("127.") or not name:
            continue
        out.append({"id": name, "name": desc, "ip": ip, "default": name == default})
    return out


def default_interface() -> str | None:
    """The interface your computer would use to reach the internet (more reliable than scapy's own default)."""
    from scapy.all import conf

    try:
        iface = conf.route.route("8.8.8.8")[0]
        return getattr(iface, "network_name", None) or str(iface)
    except Exception:
        return None


class LiveSniffer:
    """Calls `on_packet(ts_us, raw)` for every TCP/UDP frame seen on `iface`."""

    def __init__(self, iface: str | None, on_packet: Callable[[int, bytes], None]):
        from scapy.all import AsyncSniffer

        self.iface = iface or default_interface()
        if not self.iface:
            raise RuntimeError("No network interface found.")

        def handle(p):
            on_packet(int(float(p.time) * 1_000_000), bytes(p))

        self._sniffer = AsyncSniffer(iface=self.iface, store=False, prn=handle, filter="tcp or udp")

    def start(self) -> None:
        self._sniffer.start()
        time.sleep(1.0)  # failures (no Npcap, no permission, bad interface) surface within this moment
        err = getattr(self._sniffer, "exception", None)
        if err is not None or not self._sniffer.running:
            raise RuntimeError(f"Could not start capture on '{self.iface}': {err or 'sniffer stopped'}")

    def stop(self) -> None:
        try:
            if self._sniffer.running:
                self._sniffer.stop()
        except Exception:
            pass
