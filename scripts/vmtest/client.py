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

from httpload import HttpLoad, Link


def mac(s):
    """'aa:bb:cc:dd:ee:ff' -> 6 raw bytes."""
    return bytes(int(x, 16) for x in s.split(":"))


def csum(data):
    """Internet checksum (RFC 1071) over data."""
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack(f"!{len(data) // 2}H", data))
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
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total,
        0x1234,
        0,
        a.ttl,
        17,
        0,
        socket.inet_aton(a.src_ip),
        socket.inet_aton(a.dst_ip),
    )
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
            # Small frames (ARP, ACKs, SYNs) must go out at once, not wait to be batched
            # (Nagle), or the link itself would add tens of milliseconds to every exchange.
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
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


def wire_for(a, payload):
    """Length-framed wire bytes and packets-per-block for one payload size or the IMIX."""
    if payload == "imix":
        parts = []
        for size, n in ((18, 7), (548, 4), (1472, 1)):
            a.size = size
            f = build_frame(a)
            parts += [struct.pack("!I", len(f)) + f] * n
        return b"".join(parts), len(parts)
    a.size = int(payload)
    f = build_frame(a)
    return struct.pack("!I", len(f)) + f, 1


def serve(a):
    """Hold one connection open and run commands from stdin (see --serve).

    Commands (one per line; each runs in its own thread, so a flood and an HTTP
    test can run at the same time, which is the point):
      FLOOD <pps> <seconds> <payload-bytes|imix> <settle-seconds> [<chunk-packets>]
          replies "sent <count>". A chunk size above 0 sends in small pieces, so the
          HTTP frames interleave with the flood instead of queueing behind a burst.
      HTTP <requests-per-second> <seconds> <delay-seconds> <result-file>
          fetches a page through the same NIC, starting after <delay>; replies "http done".
      QUIT
    """
    sys.setswitchinterval(0.0005)  # let the HTTP threads run promptly beside the flood
    sock = connect(a.port)
    link = Link(sock, a.src_mac, a.http_ip, a.dst_mac, a.dst_ip)
    threading.Thread(target=link.rx_loop, daemon=True).start()
    http = HttpLoad(link)
    out_lock = threading.Lock()

    def reply(text):
        with out_lock:
            print(text, flush=True)

    def flood(rate, secs, payload, settle, chunk):
        wire, per = wire_for(a, payload)
        blocks = max(1, int((chunk if chunk > 0 else rate // 100) // per))
        piece = wire * blocks
        sent, t0 = 0, time.time()
        while time.time() < t0 + secs:
            link.send_raw(piece)
            sent += blocks * per
            ahead = sent / rate - (time.time() - t0)
            if ahead > 0:
                time.sleep(ahead)
        time.sleep(settle)  # let the guest drain its backlog before the next step
        reply(f"sent {sent}")

    def web(rate, secs, delay, outfile):
        http.run(rate, secs, delay, outfile)
        reply("http done")

    print("ready", flush=True)
    for line in sys.stdin:
        w = line.split()
        if not w:
            continue
        if w[0] == "QUIT":
            break
        try:
            if w[0] == "FLOOD" and len(w) in (5, 6):
                args = (
                    float(w[1]),
                    float(w[2]),
                    w[3],
                    float(w[4]),
                    int(w[5]) if len(w) == 6 else 0,
                )
                threading.Thread(target=flood, args=args, daemon=True).start()
            elif w[0] == "HTTP" and len(w) == 5:
                args = (float(w[1]), float(w[2]), float(w[3]), w[4])
                threading.Thread(target=web, args=args, daemon=True).start()
            else:
                reply("error bad command")
        except ValueError:
            reply("error bad command")
    time.sleep(0.5)
    sock.shutdown(socket.SHUT_WR)
    time.sleep(0.2)
    sock.close()
    return 0


def main():
    p = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    p.add_argument("--port", type=int, required=True, help="QEMU stream socket port")
    p.add_argument("--dst-mac", required=True)
    p.add_argument("--src-mac", default="02:00:00:00:00:01")
    p.add_argument("--dst-ip", required=True)
    p.add_argument("--src-ip", required=True)
    p.add_argument("--sport", type=int, default=40000)
    p.add_argument("--dport", type=int, default=19999)
    p.add_argument("--size", type=int, default=20, help="UDP payload bytes")
    p.add_argument(
        "--imix",
        action="store_true",
        help="send the standard Internet mix instead of --size: 7 parts 64-byte, 4 parts "
        "594-byte and 1 part 1518-byte Ethernet frames (UDP payloads of 18, 548 and 1472 bytes)",
    )
    p.add_argument("--ttl", type=int, default=64)
    p.add_argument("--count", type=int, help="send exactly N packets")
    p.add_argument("--pace", type=float, default=0.0, help="seconds between packets (with --count)")
    p.add_argument("--duration", type=float, help="send for N seconds (needs --rate)")
    p.add_argument("--rate", type=float, help="packets per second (with --duration)")
    p.add_argument(
        "--serve",
        action="store_true",
        help="stay connected and run commands read from stdin, one per line: "
        "'FLOOD <pps> <seconds> <payload-bytes|imix> <settle-seconds> [<chunk>]' prints the packet "
        "count when done, 'HTTP <rps> <seconds> <delay> <file>' fetches pages through the same NIC, "
        "'QUIT' disconnects. Used by scripts/vmbench.sh, which must never drop the "
        "connection mid-run (QEMU 11.x crashes when it flushes queued packets to a closed stream)",
    )
    p.add_argument(
        "--http-ip",
        default="10.77.0.60",
        help="source address of the HTTP test client in --serve mode (must not be blocklisted)",
    )
    p.add_argument(
        "--linger",
        type=float,
        default=0.2,
        help="seconds to keep the connection open after the last packet, so the VM can drain "
        "its backlog before QEMU sees the disconnect (use a few seconds after heavy floods)",
    )
    a = p.parse_args()
    if a.serve:
        return serve(a)
    if (a.count is None) == (a.duration is None):
        p.error("give exactly one of --count or --duration")
    if a.duration is not None and not a.rate:
        p.error("--duration needs --rate")

    if a.imix:
        # One 12-packet block holds the mix; sending whole blocks keeps the ratio exact.
        parts = []
        for payload, n in ((18, 7), (548, 4), (1472, 1)):
            a.size = payload
            f = build_frame(a)
            parts += [struct.pack("!I", len(f)) + f] * n
        wire, per_wire = b"".join(parts), len(parts)
    else:
        frame = build_frame(a)
        wire, per_wire = struct.pack("!I", len(frame)) + frame, 1
    s = connect(a.port)
    threading.Thread(target=drain, args=(s,), daemon=True).start()

    sent = 0
    if a.count is not None:
        for _ in range(-(-a.count // per_wire)):
            s.sendall(wire)
            sent += per_wire
            if a.pace:
                time.sleep(a.pace)
    else:
        # Send in small batches and sleep to hold the requested average rate.
        t0 = time.time()
        end = t0 + a.duration
        batch = max(1, int(a.rate // 100 // per_wire))
        while time.time() < end:
            s.sendall(wire * batch)
            sent += batch * per_wire
            ahead = sent / a.rate - (time.time() - t0)
            if ahead > 0:
                time.sleep(ahead)
    # Let TCP flush, then close; QEMU keeps listening for the next client.
    # Closing while QEMU still has a backlog queued for a slow guest has crashed
    # QEMU 11.x (a NULL dereference in the stream netdev), so let it drain first.
    time.sleep(a.linger)
    s.shutdown(socket.SHUT_WR)
    time.sleep(0.2)
    s.close()
    print(sent)
    return 0


if __name__ == "__main__":
    sys.exit(main())
