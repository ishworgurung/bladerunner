#!/usr/bin/env python3
"""Guest-side receiver: counts UDP datagrams that actually reached userspace.

If the bladerunner XDP program drops a packet it never gets here, so these
counts are the ground truth for "was it delivered". Counts are keyed
"<src ip>:<src port>:<dst port>" and written atomically to a JSON file a few
times a second so the host can read them over SSH at any moment.

  rx.py OUTFILE PORT [PORT...]
"""

import json
import os
import selectors
import socket
import sys
import time

out, ports = sys.argv[1], [int(x) for x in sys.argv[2:]]
sel = selectors.DefaultSelector()
for port in ports:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 << 20)
    s.bind(("0.0.0.0", port))
    s.setblocking(False)
    sel.register(s, selectors.EVENT_READ, port)

counts = {}
last = 0.0
while True:
    for key, _ in sel.select(timeout=0.2):
        # Drain everything queued on this socket in one go.
        while True:
            try:
                _, (ip, sport) = key.fileobj.recvfrom(65535)
            except BlockingIOError:
                break
            k = f"{ip}:{sport}:{key.data}"
            counts[k] = counts.get(k, 0) + 1
    now = time.time()
    if now - last >= 0.25:
        last = now
        tmp = out + ".tmp"
        with open(tmp, "w") as f:
            json.dump(counts, f)
        os.replace(tmp, out)
