#!/usr/bin/env bash
# Cross-architecture integration test: boots QEMU virtual machines for x86-64,
# aarch64 and riscv64, loads the matching bladerunner binary onto each VM's test
# NIC, and drives traffic at it from this host as if the host were a remote client.
#
#   scripts/vmtest.sh                     # all three architectures
#   scripts/vmtest.sh x86_64              # just one
#   scripts/vmtest.sh --boot-only riscv64 # check that the VM boots and SSH works
#
# Needs no root: the host talks to the VM over a QEMU socket, not a TAP device.
# See docs/OPERATIONS.md ("VM tests") for requirements and how it works.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(dirname "$HERE")
# shellcheck disable=SC2034  # read by scripts/lib/common.sh
LOG_TAG=vmtest
# shellcheck source=lib/common.sh
source "$HERE/lib/common.sh"
# shellcheck source=lib/assert_summary.sh
source "$HERE/lib/assert_summary.sh"
# shellcheck source=lib/vm.sh
source "$HERE/lib/vm.sh"

usage() {
  cat <<EOF
usage: $0 [options] [arch...]
  arch              x86_64, aarch64 and/or riscv64 (default: all three)
  --bladerunner-dir DIR      directory holding bladerunner-linux-{amd64,arm64,riscv64} (default: dist)
  --xdp-mode MODE   generic (default) or native (needs virtio-net native XDP in the guest)
  --work DIR        working directory (default: a fresh temp dir)
  --keep            keep the working directory (disk overlays, logs, keys)
  --boot-only       boot each VM and check SSH, then stop (no tests)
  --no-redis        skip the Redis-feed phase (it needs Docker on the host)
  -h, --help
Environment: VMTEST_CACHE (image cache), VMTEST_MEM, VMTEST_SMP.
EOF
}

BLADERUNNER_DIR=$ROOT/dist; XDP_MODE=generic; WORK=; KEEP=0; BOOT_ONLY=0; NO_REDIS=0; ARCHES=()
while [ $# -gt 0 ]; do
  case $1 in
    --bladerunner-dir) BLADERUNNER_DIR=$2; shift 2 ;;
    --xdp-mode) XDP_MODE=$2; shift 2 ;;
    --work) WORK=$2; shift 2 ;;
    --keep) KEEP=1; shift ;;
    --boot-only) BOOT_ONLY=1; shift ;;
    --no-redis) NO_REDIS=1; shift ;;
    -h|--help) usage; exit 0 ;;
    x86_64|aarch64|riscv64) ARCHES+=("$1"); shift ;;
    *) usage >&2; die "unknown argument: $1" ;;
  esac
done
[ ${#ARCHES[@]} -gt 0 ] || ARCHES=(x86_64 aarch64 riscv64)
case $XDP_MODE in generic|native) ;; *) die "--xdp-mode must be generic or native" ;; esac
export VM_XDP_MODE=$XDP_MODE   # read by scripts/lib/vm.sh when it builds the test NIC
need python3 curl ssh scp

if [ -z "$WORK" ]; then WORK=$(mktemp -d "${TMPDIR:-/tmp}/bladerunner-vmtest.XXXXXX"); fi
mkdir -p "$WORK"
if [ "$KEEP" = 1 ]; then log "work dir kept: $WORK"; else on_exit "rm -rf '$WORK'"; fi

# ---- host-side Redis (for the Redis-feed phase) ------------------------------
# A throwaway Redis runs in Docker on the host. The guest reaches the host through
# QEMU's user-mode network at 10.0.2.2, which lands on the host's loopback.
# Pinned by digest (redis 7 alpine) so a moved tag cannot change what the test runs.
REDIS_IMAGE=${VMTEST_REDIS_IMAGE:-redis@sha256:7f7d30b7fdd09467bac58198a1f166dd69789d348d4fe859cccb20e0cf287fbe}
REDIS_NAME=bladerunner-vmtest-redis-$$; REDIS_PORT=
if [ "$NO_REDIS" = 0 ] && [ "$BOOT_ONLY" = 0 ]; then
  if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
    REDIS_PORT=$(free_port)
    on_exit "docker rm -f '$REDIS_NAME' >/dev/null 2>&1"
    docker run -d --name "$REDIS_NAME" -p "127.0.0.1:$REDIS_PORT:6379" "$REDIS_IMAGE" >/dev/null \
      || die "could not start the Redis container (use --no-redis to skip)"
    retry 50 0.2 docker exec "$REDIS_NAME" redis-cli ping >/dev/null || die "Redis did not start"
    log "host Redis ready on 127.0.0.1:$REDIS_PORT (guests see it as 10.0.2.2:$REDIS_PORT)"
  else
    warn "Docker not available: skipping the Redis-feed phase"
  fi
fi
rcli() { docker exec "$REDIS_NAME" redis-cli "$@" >/dev/null; }

# ---- host-side helpers -------------------------------------------------------

# send ARGS...: inject UDP datagrams into the VM's test NIC as a chosen sender.
send() {
  python3 "$HERE/vmtest/client.py" --port "$VM_NET_PORT" --dst-mac "$VM_MAC_TEST" \
    --dst-ip "$VM_TEST_IP" "$@" >/dev/null
}

# rx_get SRC_IP SPORT DPORT: how many such datagrams the guest receiver saw.
rx_get() {
  vm_ssh 'cat /tmp/rx.json' 2>/dev/null | python3 -c '
import json,sys
print(json.load(sys.stdin).get(sys.argv[1], 0))' "$1:$2:$3"
}

# bladerunner ARGS...: run the bladerunner CLI in the guest against the running daemon.
# The exact command line is echoed (to stderr) before it runs.
bladerunner() {
  local cmd="sudo /home/$VM_USER/bladerunner $* --pin /sys/fs/bpf/bladerunner-vmtest"
  log "$arch: \$ ssh ubuntu@vm '$cmd'"
  vm_ssh "$cmd"
}

# ---- the per-architecture test ----------------------------------------------

# Traffic scale. Emulated CPUs cannot take tens of thousands of packets per
# second, so the flood and thresholds shrink when the guest is not accelerated.
set_scale() {
  if [ "$VM_SLOW" = 0 ]; then
    BASE_PPS=800;  FLOOD_PPS=20000; MIN_PPS=4000; TUPLE_PPS=2000; HH_PPS=3000
    PACE=0.002;    SETTLE=1;        TTL=4
  else
    BASE_PPS=100;  FLOOD_PPS=1500;  MIN_PPS=600;  TUPLE_PPS=300;  HH_PPS=500
    PACE=0.01;     SETTLE=3;        TTL=8
  fi
}

# write_config PATH: the daemon config pushed to the guest. Rate-limit classes
# are unlimited so only the filters under test act (as in scripts/e2e_lo.sh).
write_config() {
  cat > "$1" <<YAML
interface: test0
mode: $XDP_MODE
dry_run: false
pin_dir: /sys/fs/bpf/bladerunner-vmtest
metrics: 127.0.0.1:9199
blocklist: [$VM_SUBNET.101]
sample_rate: 8
detect: {interval: 500ms, min_pps: $MIN_PPS, trigger_factor: 3, release_after: 3s, alpha: 0.2}
fingerprint: {min_tuple_pps: $TUPLE_PPS, min_share: 0.2, rule_ttl: 20s, baseline_alpha: 0.5}
heavy_hitter: {pps: $HH_PPS, windows: 2, block_ttl: 60s}
${REDIS_PORT:+redis: {enabled: true, addr: "10.0.2.2:$REDIS_PORT", key_prefix: vmtest-$VM_ARCH, poll_interval: 1s, timeout: 500ms}}
limits:
  normal: {udp: {pps: 0, burst: 0}, syn: {pps: 0, burst: 0}, dns: {pps: 0, burst: 0}, icmp: {pps: 0, burst: 0}}
  attack: {udp: {pps: 0, burst: 0}, syn: {pps: 0, burst: 0}, dns: {pps: 0, burst: 0}, icmp: {pps: 0, burst: 0}}
YAML
}

run_arch() {
  local arch=$1 idx=$2 binary fails0=$ASSERT_FAILS
  vm_arch_init "$arch" "$idx" "$WORK"
  set_scale
  binary=$BLADERUNNER_DIR/bladerunner-linux-$VM_GOARCH
  if [ "$BOOT_ONLY" = 0 ]; then
    [ -x "$binary" ] || die "$binary not found; run 'make dist' or pass --bladerunner-dir"
  fi
  log "=== $arch ($VM_GOARCH) ==="
  vm_prepare
  vm_start
  vm_wait_ready
  if [ "$BOOT_ONLY" = 1 ]; then
    log "$arch: boot OK; test0 = $(vm_ssh "ip -br addr show test0")"
    vm_stop; return 0
  fi

  # Deliver the binary, the receiver and the config.
  write_config "$VM_DIR/bladerunner.yaml"
  vm_scp "$binary" "$VM_DIR/bladerunner.yaml" "$HERE/vmtest/rx.py" "/home/$VM_USER/"
  vm_ssh "mv ~/bladerunner-linux-$VM_GOARCH ~/bladerunner && chmod +x ~/bladerunner"
  # shellcheck disable=SC2088  # the tilde must expand on the guest, not here
  log "$arch: $(vm_ssh '~/bladerunner version')"

  # Start the receiver first, then the daemon. The daemon attaches XDP to test0
  # only; SSH runs over mgmt0 and is never filtered.
  vm_ssh 'nohup python3 ~/rx.py /tmp/rx.json 19999 19998 19997 >/tmp/rx.log 2>&1 &'
  vm_ssh "sudo sh -c 'nohup /home/$VM_USER/bladerunner run -c /home/$VM_USER/bladerunner.yaml >/tmp/bladerunner.log 2>&1 &'"
  if ! retry 120 1 vm_ssh 'grep -q msg=attached /tmp/bladerunner.log'; then
    warn "$arch: daemon did not attach"; vm_ssh 'cat /tmp/bladerunner.log' >&2 || true
    ASSERT_FAILS=$((ASSERT_FAILS+1)); vm_stop; return 1
  fi
  _pass "$arch: daemon attached XDP ($XDP_MODE) to test0"
  # Prove the attach mode, not just that the daemon says so: `ip -d link` puts an
  # "xdp" flag on the interface line for a driver-mode program and "xdpgeneric"
  # for a generic one (the "prog/xdp id N" line below it is the same for both).
  local ipd; ipd=$(vm_ssh 'ip -d link show test0')
  # shellcheck disable=SC2016  # the $(...) and quotes must expand on the guest
  log "$arch: test0 driver: $(vm_ssh 'basename "$(readlink /sys/class/net/test0/device/driver)"'), queues: $(vm_ssh 'ls /sys/class/net/test0/queues | tr "\n" " "')"
  if [ "$XDP_MODE" = native ]; then
    assert_true "$arch: XDP is attached in driver (native) mode" grep -qE ' mtu [0-9]+ xdp ' <<<"$ipd"
  else
    assert_true "$arch: XDP is attached in generic mode" grep -qE ' mtu [0-9]+ xdpgeneric ' <<<"$ipd"
  fi
  on_exit "vm_ssh 'sudo pkill -x bladerunner' >/dev/null 2>&1"
  sleep 1
  log "$arch: $(bladerunner status | sed -n 1,4p | tr '\n' ' ')"

  # --- Phase 1: verdicts on real traffic ------------------------------------
  # Pass-direction checks tolerate a little loss (a slow emulated guest can drop
  # a frame); drop-direction checks are exact: a blocked packet must never arrive.
  log "$arch: phase 1: static filters"
  send --src-ip "$VM_SUBNET".100 --sport 40000 --count 50 --pace "$PACE"
  send --src-ip "$VM_SUBNET".101 --sport 40001 --count 50 --pace "$PACE"
  send --src-ip "$VM_SUBNET".104 --sport 123 --size 400 --count 50 --pace "$PACE"
  send --src-ip "$VM_SUBNET".105 --sport 123 --size 20  --count 50 --pace "$PACE"
  sleep "$SETTLE"
  assert_ge "$arch: clean source is delivered"            "$(rx_get "$VM_SUBNET".100 40000 19999)" 45
  assert_eq "$arch: blocklisted source is dropped"        "$(rx_get "$VM_SUBNET".101 40001 19999)" 0
  assert_eq "$arch: amplification (sport 123, 400 B) dropped" "$(rx_get "$VM_SUBNET".104 123 19999)" 0
  assert_ge "$arch: small packet from sport 123 delivered" "$(rx_get "$VM_SUBNET".105 123 19999)" 45

  # --- Phase 2: runtime block with an in-kernel TTL ---------------------------
  log "$arch: phase 2: block with TTL ${TTL}s"
  bladerunner block "$VM_SUBNET".103 --ttl "${TTL}s" >/dev/null
  send --src-ip "$VM_SUBNET".103 --sport 40003 --count 10 --pace "$PACE"
  sleep "$SETTLE"
  assert_eq "$arch: TTL-blocked source dropped while active" "$(rx_get "$VM_SUBNET".103 40003 19999)" 0
  sleep $((TTL + 1))
  send --src-ip "$VM_SUBNET".103 --sport 40004 --count 10 --pace "$PACE"
  sleep "$SETTLE"
  assert_ge "$arch: source delivered again after the TTL expired" "$(rx_get "$VM_SUBNET".103 40004 19999)" 9

  # --- Phase 3: dry-run can be flipped live -----------------------------------
  log "$arch: phase 3: dry-run toggle"
  bladerunner dryrun on >/dev/null
  assert_eq "$arch: status reports dry-run on" "$(bladerunner status | awk '$1=="dry-run"{print $2}')" on
  # In dry-run the blocklisted source must now get through (counted, not dropped).
  send --src-ip "$VM_SUBNET".101 --sport 40005 --count 20 --pace "$PACE"
  sleep "$SETTLE"
  assert_ge "$arch: dry-run lets would-be drops through" "$(rx_get "$VM_SUBNET".101 40005 19999)" 15
  bladerunner dryrun off >/dev/null

  # --- Phase 4: closed loop: baseline, flood, detection -----------------------
  log "$arch: phase 4: baseline ${BASE_PPS} pps then flood ${FLOOD_PPS} pps"
  send --src-ip "$VM_SUBNET".100 --sport 40000 --size 60 --duration 6 --rate "$BASE_PPS"
  send --src-ip "$VM_SUBNET".109 --sport 4444 --dport 19997 --size 300 --duration 8 --rate "$FLOOD_PPS"
  sleep "$SETTLE"
  assert_true "$arch: attack detected" retry 10 1 vm_ssh 'grep -q "attack state changed" /tmp/bladerunner.log'
  log "$arch: rules/blocks after the flood:"
  bladerunner rules 2>&1 | sed 's/^/    /' >&2 || true
  bladerunner list block 2>&1 | sed 's/^/    /' >&2 || true
  vm_ssh 'curl -s 127.0.0.1:9199/metrics | grep -E "^bladerunner_(attack|attacks_total|autoblocks_total|fp_rules_active|offered_pps)"' 2>/dev/null | sed 's/^/    /' >&2 || true

  # --- Phase 5: shared lists from Redis, and fail-open on an outage ------------
  if [ -n "$REDIS_PORT" ]; then
    local K="vmtest-$arch" polls=$((SETTLE + 3))
    log "$arch: phase 5: Redis feed (host Redis at 10.0.2.2:$REDIS_PORT)"
    rcli SET "$K:block:$VM_SUBNET.106/32" "vmtest"
    assert_true "$arch: block range from Redis reaches the kernel map" \
      retry 30 1 vm_ssh "sudo /home/$VM_USER/bladerunner list block --pin /sys/fs/bpf/bladerunner-vmtest | grep -q '$VM_SUBNET.106/32'"
    send --src-ip "$VM_SUBNET".106 --sport 40006 --count 10 --pace "$PACE"
    sleep "$SETTLE"
    assert_eq "$arch: source blocked via Redis is dropped" "$(rx_get "$VM_SUBNET".106 40006 19999)" 0

    # The allowlist from Redis beats the YAML blocklist entry for .101.
    rcli SET "$K:allow:$VM_SUBNET.101/32" "vmtest"
    assert_true "$arch: allow range from Redis reaches the kernel map" \
      retry 30 1 vm_ssh "sudo /home/$VM_USER/bladerunner list allow --pin /sys/fs/bpf/bladerunner-vmtest | grep -q '$VM_SUBNET.101/32'"
    send --src-ip "$VM_SUBNET".101 --sport 40008 --count 10 --pace "$PACE"
    sleep "$SETTLE"
    assert_ge "$arch: Redis allow overrides a YAML block" "$(rx_get "$VM_SUBNET".101 40008 19999)" 9

    # Outage: kill Redis. Existing entries must stay in force (fail-open) and the
    # daemon must report the outage, but traffic handling must be unaffected.
    log "$arch: stopping Redis (simulated outage)"
    docker stop -t 0 "$REDIS_NAME" >/dev/null
    sleep "$polls"
    assert_true "$arch: daemon reports redis_up 0 during the outage" \
      retry 15 1 vm_ssh "curl -s 127.0.0.1:9199/metrics | grep -q '^bladerunner_redis_up 0'"
    send --src-ip "$VM_SUBNET".106 --sport 40009 --count 10 --pace "$PACE"
    send --src-ip "$VM_SUBNET".100 --sport 40010 --count 10 --pace "$PACE"
    sleep "$SETTLE"
    assert_eq "$arch: Redis-fed block still enforced while Redis is down" "$(rx_get "$VM_SUBNET".106 40009 19999)" 0
    assert_ge "$arch: clean traffic unaffected by the outage" "$(rx_get "$VM_SUBNET".100 40010 19999)" 9

    # Recovery: Redis comes back empty, so the feed's entries are withdrawn.
    docker start "$REDIS_NAME" >/dev/null
    retry 50 0.2 docker exec "$REDIS_NAME" redis-cli ping >/dev/null
    assert_true "$arch: feed recovers and applies the (now empty) lists" \
      retry 30 1 vm_ssh "curl -s 127.0.0.1:9199/metrics | grep -q '^bladerunner_redis_up 1'"
    send --src-ip "$VM_SUBNET".106 --sport 40011 --count 10 --pace "$PACE"
    sleep "$SETTLE"
    assert_ge "$arch: source delivered after Redis withdrew the block" "$(rx_get "$VM_SUBNET".106 40011 19999)" 9
    bladerunner list block 2>&1 | sed 's/^/    /' >&2 || true
  fi

  if [ "$ASSERT_FAILS" -gt "$fails0" ]; then
    warn "$arch: failures: dumping daemon log"; vm_ssh 'tail -n 40 /tmp/bladerunner.log' >&2 || true
  fi
  vm_ssh 'sudo pkill -x bladerunner' >/dev/null 2>&1 || true
  vm_stop
  [ "$ASSERT_FAILS" -eq "$fails0" ]
}

idx=1; rc=0
for a in "${ARCHES[@]}"; do
  run_arch "$a" "$idx" || rc=1
  idx=$((idx+1))
done
if [ "$BOOT_ONLY" = 1 ]; then log "boot check finished"; exit $rc; fi
assert_summary "vmtest (${ARCHES[*]})" || rc=1
exit $rc
