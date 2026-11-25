"""A tiny TCP + HTTP client that speaks over the VM's raw test link.

The benchmark's test NIC is a rootless QEMU "stream" socket, so the host has no
network stack on it. To measure what a genuine web request experiences while a
flood is running, this module implements just enough of ARP, TCP and HTTP/1.0 to
fetch a page through the SAME virtual NIC (and the same XDP hook) as the flood:

  * it answers the guest's ARP requests for its own address;
  * it opens connections (SYN, handshake), sends one GET, ACKs the reply,
    retransmits its own SYN and request if they are lost, and then closes;
  * it starts requests at a FIXED RATE whether or not earlier ones finished
    (an "open loop"), so a slow server cannot hide latency by receiving fewer
    requests;
  * it records, per request, the connect time, the time to first byte and the
    total time, measured with a monotonic clock.

It is deliberately small. It does not do congestion control of its own (the
guest's TCP does that when sending), selective acknowledgements or reordering
buffers: out-of-order segments are answered with a duplicate ACK and the guest
retransmits. See docs/BENCHMARKS.md for what this does and does not measure.
"""

import json
import random
import re
import socket
import struct
import threading
import time

FIN, SYN, RST, PSH, ACK = 0x01, 0x02, 0x04, 0x08, 0x10


def csum(data):
    """Internet checksum (RFC 1071)."""
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def mac(s):
    return bytes(int(x, 16) for x in s.split(":"))


class Link:
    """The shared QEMU stream connection. Writers take a lock per write, so the
    flood and the HTTP frames interleave on frame boundaries, in arrival order."""

    def __init__(self, sock, our_mac, our_ip, peer_mac, peer_ip):
        self.sock = sock
        self.lock = threading.Lock()
        self.mac, self.ip = mac(our_mac), socket.inet_aton(our_ip)
        self.peer_mac, self.peer_ip = mac(peer_mac), socket.inet_aton(peer_ip)
        self.http = None  # set by HttpLoad

    def send_raw(self, data):
        with self.lock:
            self.sock.sendall(data)

    def send_frame(self, frame):
        if len(frame) < 60:
            frame += b"\0" * (60 - len(frame))
        self.send_raw(struct.pack("!I", len(frame)) + frame)

    # ---- receive side -------------------------------------------------------
    def rx_loop(self):
        buf = bytearray()
        try:
            while True:
                d = self.sock.recv(1 << 20)
                # Linux drops back to delayed ACKs after every read; ask again each time, so
                # QEMU is never held up waiting for an acknowledgement from this process.
                self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_QUICKACK, 1)
                if not d:
                    return
                buf += d
                pos = 0
                while len(buf) - pos >= 4:
                    n = int.from_bytes(buf[pos : pos + 4], "big")
                    if len(buf) - pos < 4 + n:
                        break
                    self.on_frame(bytes(buf[pos + 4 : pos + 4 + n]))
                    pos += 4 + n
                del buf[:pos]
                if self.http:
                    self.http.flush()
        except OSError:
            return

    def on_frame(self, f):
        if len(f) < 34:
            return
        et = f[12:14]
        if et == b"\x08\x06":  # ARP
            if f[20:22] == b"\x00\x01" and f[38:42] == self.ip:  # who-has our address
                reply = (
                    f[6:12]
                    + self.mac
                    + b"\x08\x06"
                    + b"\x00\x01\x08\x00\x06\x04\x00\x02"
                    + self.mac
                    + self.ip
                    + f[22:28]
                    + f[28:32]
                )
                self.send_frame(reply)
            return
        if et != b"\x08\x00" or f[23] != 6 or f[30:34] != self.ip:
            return
        ihl = (f[14] & 0x0F) * 4
        total = struct.unpack("!H", f[16:18])[0]
        t = 14 + ihl
        if len(f) < t + 20:
            return
        _, dport, seq, ack, off, flags = struct.unpack("!HHIIBB", f[t : t + 14])
        payload = f[t + (off >> 4) * 4 : 14 + total]
        if self.http:
            self.http.on_tcp(dport, seq, ack, flags, payload)


class Conn:
    __slots__ = (
        "err",
        "expect",
        "hdr",
        "iss",
        "last_rx",
        "last_tx",
        "measured",
        "pending",
        "rcv_nxt",
        "req_acked",
        "rto",
        "rx",
        "snd_nxt",
        "sport",
        "state",
        "t0",
        "t_conn",
        "t_done",
        "t_first",
        "tries",
    )

    def __init__(self, sport, measured):
        self.sport, self.iss = sport, random.getrandbits(32)
        self.snd_nxt, self.rcv_nxt = self.iss, 0
        self.t0 = time.perf_counter()
        self.t_conn = self.t_first = self.t_done = None
        self.state, self.last_tx, self.rto, self.tries = "syn", self.t0, 0.25, 0
        self.rx, self.hdr, self.expect = 0, bytearray(), None
        self.pending, self.last_rx, self.req_acked = 0, self.t0, False
        self.err, self.measured = None, measured


class HttpLoad:
    def __init__(self, link, dport=8080, path="/", timeout=8.0):
        self.link, self.dport, self.path, self.timeout = link, dport, path, timeout
        link.http = self
        self.conns = {}
        self.cl = threading.Lock()
        self.results = []
        self.next_port = 20000 + random.randrange(20000)
        self.ipid = 1

    # ---- packet construction ------------------------------------------------
    def seg(self, c, flags, seq, ack, payload=b"", options=b"", win=0xFFFF):
        L = self.link
        off = (20 + len(options)) // 4
        tcp = (
            struct.pack(
                "!HHIIBBHHH",
                c.sport,
                self.dport,
                seq & 0xFFFFFFFF,
                ack & 0xFFFFFFFF,
                off << 4,
                flags,
                win,
                0,
                0,
            )
            + options
            + payload
        )
        pseudo = L.ip + L.peer_ip + struct.pack("!BBH", 0, 6, len(tcp))
        tcp = tcp[:16] + struct.pack("!H", csum(pseudo + tcp)) + tcp[18:]
        self.ipid = (self.ipid + 1) & 0xFFFF
        ip = struct.pack(
            "!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), self.ipid, 0x4000, 64, 6, 0, L.ip, L.peer_ip
        )
        ip = ip[:10] + struct.pack("!H", csum(ip)) + ip[12:]
        L.send_frame(L.peer_mac + L.mac + b"\x08\x00" + ip + tcp)

    def send_syn(self, c):
        # MSS 1460 and a window-scale of 7, so the 16-bit window can describe 8 MiB.
        opts = b"\x02\x04\x05\xb4\x01\x03\x03\x07"
        self.seg(c, SYN, c.iss, 0, options=opts)
        c.snd_nxt = c.iss + 1
        c.last_tx = time.perf_counter()

    def send_req(self, c):
        req = f"GET {self.path} HTTP/1.0\r\nHost: bench\r\nUser-Agent: vmbench\r\n\r\n".encode()
        self.seg(c, PSH | ACK, c.iss + 1, c.rcv_nxt, req)
        c.snd_nxt = c.iss + 1 + len(req)
        c.last_tx = time.perf_counter()

    def ack(self, c):
        self.seg(c, ACK, c.snd_nxt, c.rcv_nxt)
        c.pending = 0

    # ---- connection lifecycle -----------------------------------------------
    def start(self, measured=True):
        with self.cl:
            self.next_port += 1
            if self.next_port > 60000:
                self.next_port = 20000
            c = Conn(self.next_port, measured)
            self.conns[c.sport] = c
        self.send_syn(c)

    def finish(self, c, err=None):
        with self.cl:
            if self.conns.pop(c.sport, None) is None:
                return
            c.state = "done"
            c.err = err
            if err is None:
                c.t_done = time.perf_counter()
            if c.measured:
                ms = lambda t: None if t is None else round((t - c.t0) * 1000, 3)
                self.results.append(
                    {
                        "ok": err is None,
                        "err": err,
                        "connect_ms": ms(c.t_conn),
                        "ttfb_ms": ms(c.t_first),
                        "total_ms": ms(c.t_done),
                        "bytes": c.rx,
                    }
                )
        self.seg(c, RST | ACK, c.snd_nxt, c.rcv_nxt)

    def on_tcp(self, dport, seq, ack, flags, payload):
        c = self.conns.get(dport)
        if c is None:
            return
        now = time.perf_counter()
        if flags & RST:
            self.finish(c, "reset")
            return
        if c.state == "syn":
            if flags & SYN and flags & ACK and ack == c.iss + 1:
                c.rcv_nxt = (seq + 1) & 0xFFFFFFFF
                c.t_conn, c.state, c.tries, c.rto = now, "est", 0, 0.3
                self.send_req(c)
            return
        if ack == c.snd_nxt:
            c.req_acked = True
        if flags & SYN:  # a repeated SYN-ACK: our ACK was lost
            self.ack(c)
            return
        if payload:
            if seq == c.rcv_nxt:
                data = payload
            elif ((seq - c.rcv_nxt) & 0xFFFFFFFF) >= 0x80000000:  # partly old data
                skip = (c.rcv_nxt - seq) & 0xFFFFFFFF
                if skip >= len(payload):
                    self.ack(c)  # pure duplicate
                    return
                data = payload[skip:]
            else:
                self.ack(c)  # a gap: duplicate ACK
                return
            c.rcv_nxt = (c.rcv_nxt + len(data)) & 0xFFFFFFFF
            c.rx += len(data)
            c.last_rx = now
            if c.t_first is None:
                c.t_first = now
            if c.expect is None:
                c.hdr += data
                i = c.hdr.find(b"\r\n\r\n")
                if i >= 0:
                    m = re.search(rb"Content-Length: *(\d+)", bytes(c.hdr[:i]), re.IGNORECASE)
                    if not (c.hdr.startswith(b"HTTP/1.") and b" 200" in c.hdr[:16] and m):
                        self.finish(c, "bad-response")
                        return
                    c.expect = i + 4 + int(m.group(1))
                elif len(c.hdr) > 8192:
                    self.finish(c, "bad-response")
                    return
            if c.expect is not None and c.rx >= c.expect:
                self.ack(c)
                self.finish(c)
                return
            c.pending += 1
            if c.pending >= 8:  # at most 8 segments unacknowledged ...
                self.ack(c)  # ... and flush() acknowledges the rest per batch
        if flags & FIN:
            c.rcv_nxt = (c.rcv_nxt + 1) & 0xFFFFFFFF
            self.ack(c)
            if c.expect is None or c.rx < c.expect:
                self.finish(c, "closed-early")

    def flush(self):
        """Acknowledge everything received so far. Called after each batch of frames from
        the VM, so a reply is never left waiting for a timer (an odd last segment would
        otherwise stall the sender for a delayed-ACK period)."""
        for c in list(self.conns.values()):
            if c.pending:
                self.ack(c)

    def tick(self):
        """Retransmit lost SYNs and requests, flush delayed ACKs, expire stuck requests."""
        now = time.perf_counter()
        for c in list(self.conns.values()):
            if now - c.t0 > self.timeout:
                self.finish(c, "timeout")
            elif c.state == "syn" and now - c.last_tx > c.rto:
                c.tries += 1
                c.rto = min(c.rto * 2, 2.0)
                self.send_syn(c)
            elif (
                c.state == "est"
                and not c.req_acked
                and c.t_first is None
                and now - c.last_tx > c.rto
            ):
                c.rto = min(c.rto * 2, 2.0)
                self.send_req(c)
            elif c.pending and now - c.last_rx > 0.02:
                self.ack(c)

    # ---- the load -------------------------------------------------------------
    def run(self, rate, secs, delay, outfile):
        """Warm up (ARP and so on), wait `delay`, then start `rate` requests per second for `secs`."""
        stop = threading.Event()

        def ticker():
            while not stop.is_set():
                self.tick()
                time.sleep(0.005)

        threading.Thread(target=ticker, daemon=True).start()
        self.start(measured=False)  # warm-up request, not recorded
        time.sleep(max(delay, 0.5))
        self.results.clear()
        t0, n = time.perf_counter(), 0
        while True:
            due = t0 + n / rate
            if due >= t0 + secs:
                break
            wait = due - time.perf_counter()
            if wait > 0:
                time.sleep(wait)
            self.start()
            n += 1
        end = time.perf_counter() + self.timeout + 2  # let stragglers finish or time out
        while self.conns and time.perf_counter() < end:
            time.sleep(0.05)
        stop.set()
        with open(outfile, "w") as f:
            json.dump({"rate": rate, "secs": secs, "started": n, "results": list(self.results)}, f)
        for c in list(self.conns.values()):
            self.finish(c, "abandoned")
