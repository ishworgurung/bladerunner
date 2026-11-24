#!/usr/bin/env bash
# End-to-end smoke test on loopback in XDP generic mode. Needs root, python3,
# and a built ./bladerunner (make build). Nothing leaves the host; it attaches to `lo`
# for ~30 seconds and detaches on exit.
# Strict mode: abort on any error (-e), on use of an unset variable (-u), and on
# a failure anywhere inside a pipeline (pipefail). A silent failure here would
# make the smoke test pass for the wrong reason.
set -euo pipefail
# Path to the built binary; override with BLADERUNNER=/path/to/bladerunner.
BLADERUNNER=${BLADERUNNER:-./bladerunner}
# Use a private pin directory so this test can never collide with (or detach) a real
# production instance that uses the default /sys/fs/bpf/bladerunner.
PIN=/sys/fs/bpf/bladerunner-e2e
# Scratch directory for the generated config and the daemon log.
TMP=$(mktemp -d)
# Cleanup on ANY exit: stop the daemon, remove the temp dir, and make sure the
# XDP program is detached from lo (detach is a no-op if already gone).
cleanup() {
  rc=$?
  # On failure, show the daemon log: without it a CI failure is undiagnosable.
  if [ $rc -ne 0 ] && [ -f "$TMP/bladerunner.log" ]; then echo "---- daemon log ----"; cat "$TMP/bladerunner.log"; fi
  kill $BLADERUNNER_PID 2>/dev/null || true
  wait $BLADERUNNER_PID 2>/dev/null || true
  if [ -e "$PIN" ]; then $BLADERUNNER detach --pin "$PIN" >/dev/null 2>&1 || true; fi
  rm -rf "$TMP"
  exit $rc
}
trap cleanup EXIT

# Test config. Notable choices: generic mode (works on lo), dry_run false so drops
# are real, tiny thresholds so a Python-generated flood (tens of kpps) trips the
# detector, and rate-limit classes set to unlimited so the rate limiter does not
# interfere with the filters being tested here (it has its own unit tests).
cat > "$TMP/c.yaml" <<YAML
interface: lo
mode: generic
dry_run: false
pin_dir: $PIN
metrics: 127.0.0.1:9199
blocklist: [127.0.0.2]
sample_rate: 8
detect: {interval: 500ms, min_pps: 4000, trigger_factor: 3, release_after: 3s, alpha: 0.2}
fingerprint: {min_tuple_pps: 2000, min_share: 0.2, rule_ttl: 20s, baseline_alpha: 0.5}
heavy_hitter: {pps: 3000, windows: 2, block_ttl: 60s}
limits:
  normal: {udp: {pps: 0, burst: 0}, syn: {pps: 0, burst: 0}, dns: {pps: 0, burst: 0}, icmp: {pps: 0, burst: 0}}
  attack: {udp: {pps: 0, burst: 0}, syn: {pps: 0, burst: 0}, dns: {pps: 0, burst: 0}, icmp: {pps: 0, burst: 0}}
YAML

# Start the daemon in the background and remember its PID for the trap.
$BLADERUNNER run -c "$TMP/c.yaml" 2>"$TMP/bladerunner.log" &
BLADERUNNER_PID=$!
# Wait for the daemon to report that XDP is attached (it logs "attached" only
# after loading, configuring, pinning and attaching, in that order). Loading can
# be slow on busy CI runners (map allocation), so allow up to 120s, and fail
# fast with the log if the daemon dies instead of waiting for nothing.
for _ in $(seq 240); do
  grep -q 'msg=attached' "$TMP/bladerunner.log" 2>/dev/null && break
  kill -0 $BLADERUNNER_PID 2>/dev/null || { echo "daemon exited during startup"; exit 1; }
  sleep 0.5
done
grep -q 'msg=attached' "$TMP/bladerunner.log" || { echo "daemon did not attach within 120s"; exit 1; }
# Give XDP attach a moment to settle.
sleep 1
# Phase 1: the CLI can reach the live maps.
# NOTE: output is trimmed with `sed -n 1,Np`, never `head -N`. With pipefail, head
# exiting early would SIGPIPE the producer and fail the whole script at random.
echo "== status"; $BLADERUNNER status --pin "$PIN" | sed -n 1,12p

# Phase 2: functional checks over real loopback traffic. Each case sends 50
# datagrams from a chosen source address/port and counts how many arrive.
# 127.0.0.0/8 addresses all live on lo, so binding to .2/.3/.9 gives us distinct
# "remote" sources without any network setup.
python3 - "$TMP" <<'PY'
import socket, sys, time, threading
rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
rx.bind(("127.0.0.1", 19999)); rx.settimeout(0.3)
def count(src, sport=0, n=50, size=20):
    got = 0
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((src, sport))
    for _ in range(n): s.sendto(b"x"*size, ("127.0.0.1", 19999))
    time.sleep(0.2)
    rx.settimeout(0.05)
    try:
        while True:
            rx.recvfrom(2048); got += 1
    except socket.timeout: pass
    s.close(); return got
r = {}
r["clean 127.0.0.1"] = count("127.0.0.1")
r["blocklisted 127.0.0.2"] = count("127.0.0.2")
r["amp sport 123 len>=200"] = count("127.0.0.1", 123, 50, 400)
r["amp sport 123 len<200"] = count("127.0.0.1", 123, 50, 20)
for k, v in r.items(): print(f"  {k:28s} received {v}/50")
assert r["clean 127.0.0.1"] == 50
assert r["blocklisted 127.0.0.2"] == 0
assert r["amp sport 123 len>=200"] == 0
assert r["amp sport 123 len<200"] == 50
PY

# Phase 3: add a temporary block via the CLI and verify it expires on its own, in-kernel.
echo "== runtime block with TTL"
$BLADERUNNER block 127.0.0.3 --ttl 2s --pin "$PIN"
$BLADERUNNER list block --pin "$PIN"
python3 - <<'PY'
import socket, time
rx = socket.socket(); rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); rx.bind(("127.0.0.1", 19998)); rx.settimeout(0.2)
def n(src):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind((src, 0))
    for _ in range(10): s.sendto(b"x", ("127.0.0.1", 19998))
    time.sleep(0.1); g = 0
    try:
        while True: rx.recvfrom(64); g += 1
    except socket.timeout: pass
    return g
a = n("127.0.0.3"); time.sleep(2.5); b = n("127.0.0.3")
print(f"  during ttl: {a}/10   after expiry: {b}/10"); assert a == 0 and b == 10
PY

# Phase 4: dry-run can be flipped live.
echo "== dry-run toggle"
$BLADERUNNER dryrun on --pin "$PIN"; $BLADERUNNER status --pin "$PIN" | grep dry-run
$BLADERUNNER dryrun off --pin "$PIN"

# Phase 5: the closed loop. ~6s of ~800 pps benign traffic teaches the baseline,
# then ~8s of a 40 kpps flood from one source with a fixed source port and large
# packets must be detected, fingerprinted and the source blocked.
echo "== attack simulation (baseline then flood)"
python3 - <<'PY'
import socket, time
rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); rx.bind(("127.0.0.1", 19997))
rx.setblocking(False)
def send(src, sport, size, secs, rate):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind((src, sport))
    payload = b"x"*size; end = time.time()+secs; sent = 0; t0 = time.time()
    while time.time() < end:
        for _ in range(200): s.sendto(payload, ("127.0.0.1", 19997))
        sent += 200
        ahead = sent/rate - (time.time()-t0)
        if ahead > 0: time.sleep(ahead)
    return sent
# learn a baseline of ~800 pps benign traffic
send("127.0.0.1", 40000, 60, 6, 800)
# reflection-style flood: fixed sport 4444 (not in amp table), large datagrams
send("127.0.0.9", 4444, 300, 8, 40000)
PY
sleep 1
# Show the resulting rules, blocks, counters and metrics for a human reader.
echo "== after flood"; $BLADERUNNER rules --pin "$PIN"; $BLADERUNNER list block --pin "$PIN"; $BLADERUNNER stats --pin "$PIN" | sed -n 1,14p
curl -s 127.0.0.1:9199/metrics | grep -E '^bladerunner_(attack|attacks_total|autoblocks_total|fp_rules_active|offered_pps)' || true
echo "== log"; grep -E 'attack|fingerprint|heavy' "$TMP/bladerunner.log" | sed -n 1,8p
# Hard assertion: if the detector never fired, the test fails.
grep -q 'attack state changed' "$TMP/bladerunner.log" || { echo "FAIL: attack not detected"; exit 1; }
echo "E2E OK"
