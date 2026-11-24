#!/usr/bin/env python3
"""Host-side traffic client for the VM tests.

It plays the part of a remote machine on the VM's test network. Instead of using
the host's own network stack (which would need a TAP device and root), it builds
raw Ethernet/IPv4/UDP frames and writes them to the QEMU "stream" socket that
feeds the VM's test NIC. Each frame is sent as a 4-byte big-endian length
followed by the frame bytes, which is QEMU's stream-netdev framing.

A side effect, and a useful one: the source IP, source port and TTL are chosen
freely, so one host can pose as many different senders.

Examples
  # 50 datagrams from 10.77.0.100:40000 to the VM, 5 ms apart
  client.py --port 41234 --dst-mac 52:54:00:bb:01:01 --dst-ip 10.77.0.11 \
            --src-ip 10.77.0.100 --sport 40000 --dport 19999 --count 50 --pace 0.005
  # an 8-second flood at 20000 packets per second
  client.py ... --duration 8 --rate 20000 --size 300
"""
import argparse
import socket
import struct
import sys
import threading
import time


def mac(s):
    """'aa:bb:cc:dd:ee:ff' -> 6 raw bytes."""
    return bytes(int(x, 16) for x in s.split(":"))


def csum(data):
    """Internet checksum (RFC 1071) over data."""
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def build_frame(a):
    """Build one Ethernet + IPv4 + UDP frame from the parsed arguments."""
    payload = b"x" * a.size
    udp_len = 8 + len(payload)
    # UDP checksum 0 means "not computed", which is valid for IPv4.
    udp = struct.pack("!HHHH", a.sport, a.dport, udp_len, 0) + payload
    total = 20 + len(udp)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 0x1234, 0, a.ttl, 17, 0,
                     socket.inet_aton(a.src_ip), socket.inet_aton(a.dst_ip))
    ip = ip[:10] + struct.pack("!H", csum(ip)) + ip[12:]
    eth = mac(a.dst_mac) + mac(a.src_mac) + b"\x08\x00"
    return eth + ip + udp


def connect(port, timeout=30):
    """Connect to QEMU's stream socket, retrying while it is not accepting yet."""
    end = time.time() + timeout
    while True:
        try:
            s = socket.create_connection(("127.0.0.1", port), timeout=5)
            s.settimeout(None)
            return s
        except OSError:
            if time.time() > end:
                raise
            time.sleep(0.3)


def drain(s):
    """Discard frames the VM sends back (ARP, ICMP...) so QEMU never blocks on us."""
    try:
        while s.recv(65536):
            pass
    except OSError:
        pass


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--port", type=int, required=True, help="QEMU stream socket port")
    p.add_argument("--dst-mac", required=True)
    p.add_argument("--src-mac", default="02:00:00:00:00:01")
    p.add_argument("--dst-ip", required=True)
    p.add_argument("--src-ip", required=True)
    p.add_argument("--sport", type=int, default=40000)
    p.add_argument("--dport", type=int, default=19999)
    p.add_argument("--size", type=int, default=20, help="UDP payload bytes")
    p.add_argument("--ttl", type=int, default=64)
    p.add_argument("--count", type=int, help="send exactly N packets")
    p.add_argument("--pace", type=float, default=0.0, help="seconds between packets (with --count)")
    p.add_argument("--duration", type=float, help="send for N seconds (needs --rate)")
    p.add_argument("--rate", type=float, help="packets per second (with --duration)")
    a = p.parse_args()
    if (a.count is None) == (a.duration is None):
        p.error("give exactly one of --count or --duration")
    if a.duration is not None and not a.rate:
        p.error("--duration needs --rate")

    frame = build_frame(a)
    wire = struct.pack("!I", len(frame)) + frame
    s = connect(a.port)
    threading.Thread(target=drain, args=(s,), daemon=True).start()

    sent = 0
    if a.count is not None:
        for _ in range(a.count):
            s.sendall(wire)
            sent += 1
            if a.pace:
                time.sleep(a.pace)
    else:
        # Send in small batches and sleep to hold the requested average rate.
        t0 = time.time()
        end = t0 + a.duration
        batch = max(1, int(a.rate // 100))
        while time.time() < end:
            s.sendall(wire * batch)
            sent += batch
            ahead = sent / a.rate - (time.time() - t0)
            if ahead > 0:
                time.sleep(ahead)
    # Let TCP flush, then close; QEMU keeps listening for the next client.
    s.shutdown(socket.SHUT_WR)
    time.sleep(0.2)
    s.close()
    print(sent)
    return 0


if __name__ == "__main__":
    sys.exit(main())
