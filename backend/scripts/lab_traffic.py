"""Generates a TCP port scan against a machine YOU own, so you can watch CYBER ATTACK DETECTION SYSTEM react in LIVE mode.

    python scripts/lab_traffic.py 192.168.1.50                 # scan ports 1-1024 of that machine
    python scripts/lab_traffic.py 192.168.1.50 --ports 1-200 --delay 0.002

Safety: it refuses any address that is not private (10.x, 172.16-31.x, 192.168.x). Only run it against
your own devices (a second laptop, a phone, a VM). Scanning a device that is on the same network but
isn't yours is not OK. Your own machine's loopback (127.0.0.1) is not visible to a network sniffer.
"""
import argparse
import ipaddress
import socket
import time


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("target", help="private IP of a device you own")
    ap.add_argument("--ports", default="1-1024", help="range like 1-1024")
    ap.add_argument("--delay", type=float, default=0.005, help="seconds between connection attempts")
    args = ap.parse_args()

    ip = ipaddress.ip_address(args.target)
    if not ip.is_private or ip.is_loopback:
        raise SystemExit("Refusing: target must be a private LAN address of a device you own.")
    lo, hi = (int(x) for x in args.ports.split("-"))

    open_ports = []
    for port in range(lo, hi + 1):
        with socket.socket() as s:
            s.settimeout(0.3)
            if s.connect_ex((args.target, port)) == 0:
                open_ports.append(port)
        time.sleep(args.delay)
    print(f"Scanned {hi - lo + 1} ports on {args.target}. Open: {open_ports or 'none'}")


if __name__ == "__main__":
    main()
