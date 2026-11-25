#!/usr/bin/env bash
# Local benchmark: native (driver-mode) versus generic XDP, in one KVM virtual machine.
#
#   scripts/vmbench.sh                              # 5 runs per mode, 100k pps, 10 s each
#   scripts/vmbench.sh --runs 8 --rate 150000 --duration 15
#
# Every packet the host sends comes from a blocklisted source, so the filter
# drops all of it and the only work being compared is "how much guest CPU does it
# take to receive and drop a packet" in each attach mode. Per run, modes alternate
# order so that drift (thermal, host noise) does not favour one. The same virtio-net
# card and settings are used for both modes; only the attach mode changes.
#
# What this does and does not tell you: virtio-net is a software driver, so the
# gap shows how much the skb allocation and generic hook cost, not what a real
# NIC driver would save. Treat the numbers as a lower bound on the native advantage
# and as relative, not absolute. See docs/OPERATIONS.md ("Native vs generic").
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(dirname "$HERE")
# shellcheck disable=SC2034  # read by scripts/lib/common.sh
LOG_TAG=vmbench
# shellcheck source=lib/common.sh
source "$HERE/lib/common.sh"
# shellcheck source=lib/vm.sh
source "$HERE/lib/vm.sh"

RUNS=3; RATES=1500000,3000000,4000000,5000000,6000000; CPUS=4; DURATION=10; SIZES=60,512,1472,imix; MAX_GBPS=10; GBPS=; WORK=; KEEP=0; BR_DIR=$ROOT/dist; OUT=
usage() {
  cat <<EOF
usage: $0 [options]
  --runs N        runs per mode at each rate (default 3)
  --rates LIST    comma-separated offered loads in packets per second, run in this
                  order (default 1500000,3000000,4000000,5000000,6000000)
  --rate PPS      shorthand for a single rate
  --gbps LIST     comma-separated offered loads in Gbit/s of frame data instead of
                  --rates: each is converted to packets per second for every size, and
                  --max-gbps does not apply (use it to push past 10 Gbit/s)
  --cpus N        virtual CPUs in the VM (default 4)
  --duration S    seconds measured per run (default 10)
  --sizes LIST    comma-separated UDP payload sizes in bytes, and/or "imix" (default
                  60,512,1472,imix). imix is the standard Internet mix: 7 parts 64-byte,
                  4 parts 594-byte and 1 part 1518-byte Ethernet frames
  --size BYTES    shorthand for a single size
  --max-gbps G    cap the offered load at G Gbit/s of frame data (default 10): big
                  packets cannot reach the packet rates that small ones can, so each
                  rate is reduced to fit, and repeated rates are run once
  --json FILE     also write the results as JSON
  --work DIR      working directory (default: a fresh temp dir)
  --keep          keep the working directory
  -h, --help
Needs KVM (x86-64 host): the emulated architectures are far too slow to measure.
EOF
}
while [ $# -gt 0 ]; do
  case $1 in
    --runs) RUNS=$2; shift 2 ;;
    --rates) RATES=$2; shift 2 ;;
    --rate) RATES=$2; shift 2 ;;
    --gbps) GBPS=$2; shift 2 ;;
    --cpus) CPUS=$2; shift 2 ;;
    --duration) DURATION=$2; shift 2 ;;
    --sizes) SIZES=$2; shift 2 ;;
    --size) SIZES=$2; shift 2 ;;
    --max-gbps) MAX_GBPS=$2; shift 2 ;;
    --json) OUT=$2; shift 2 ;;
    --work) WORK=$2; shift 2 ;;
    --keep) KEEP=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; die "unknown argument: $1" ;;
  esac
done
need python3 curl ssh scp
[ -x "$BR_DIR/bladerunner-linux-amd64" ] || die "$BR_DIR/bladerunner-linux-amd64 not found; run 'make dist'"

if [ -z "$WORK" ]; then WORK=$(mktemp -d "${TMPDIR:-/tmp}/bladerunner-vmbench.XXXXXX"); fi
mkdir -p "$WORK"
if [ "$KEEP" = 1 ]; then log "work dir kept: $WORK"; else on_exit "rm -rf '$WORK'"; fi

# Same NIC settings for both modes (the native-capable ones), see lib/vm.sh.
export VM_XDP_MODE=native
export VMTEST_SMP=$CPUS
vm_arch_init x86_64 1 "$WORK"
[ "$VM_SLOW" = 0 ] || die "no KVM acceleration here: results would measure the emulator, not XDP"
vm_prepare
vm_start
vm_wait_ready

PIN=/sys/fs/bpf/bladerunner-vmtest
SRC=$VM_SUBNET.50

write_config() { # MODE
  cat > "$VM_DIR/bladerunner.yaml" <<YAML
interface: test0
mode: $1
dry_run: false
pin_dir: $PIN
metrics: 127.0.0.1:9199
blocklist: [$SRC]
sample_rate: 0                  # no sampling: measure the bare drop path
rate_limit: false
fingerprint: {enabled: false}
heavy_hitter: {enabled: false}
YAML
}

start_daemon() { # MODE
  write_config "$1"
  vm_scp "$VM_DIR/bladerunner.yaml" "/home/$VM_USER/"
  vm_ssh "sudo sh -c 'nohup /home/$VM_USER/bladerunner run -c /home/$VM_USER/bladerunner.yaml >/tmp/bladerunner.log 2>&1 &'"
  retry 60 1 vm_ssh 'grep -q msg=attached /tmp/bladerunner.log' || { vm_ssh 'cat /tmp/bladerunner.log' >&2; die "daemon did not attach ($1)"; }
  local ipd; ipd=$(vm_ssh 'ip -d link show test0')
  case $1 in
    native)  grep -qE ' mtu [0-9]+ xdp '        <<<"$ipd" || die "not in driver mode" ;;
    generic) grep -qE ' mtu [0-9]+ xdpgeneric ' <<<"$ipd" || die "not in generic mode" ;;
  esac
}

# After a very heavy flood the guest can be too busy to answer SSH for a while.
wait_guest() { retry 90 2 vm_ssh true || die "guest stopped answering SSH"; }

stop_daemon() {
  wait_guest
  retry 5 2 vm_ssh 'sudo pkill -x bladerunner' >/dev/null 2>&1 || true
  retry 60 1 vm_ssh "! test -e $PIN" || die "daemon did not release $PIN"
}

# The sampler runs in the guest: it reads /proc/stat and the drop counter, sleeps
# for the measured window, reads them again and prints both snapshots.
# shellcheck disable=SC2016  # this text runs on the guest; its $(...) must not expand here
SAMPLER='
cnt() { curl -s 127.0.0.1:9199/metrics | sed -n "s/^bladerunner_packets_total{reason=\"blocklist\"} //p"; }
sleep 2                       # let the sender ramp up
a=$(grep "^cpu " /proc/stat); p0=$(cnt)
sleep '"$DURATION"'
b=$(grep "^cpu " /proc/stat); p1=$(cnt)
echo "$a|$b|$p0|$p1"'

# measure yes|no RATE SIZE: sets MEASURE_OUT to "busy_jiffies total_jiffies packets sent", or FAIL if
# the guest could not be sampled (it was saturated and stopped answering SSH).
measure() {
  local traffic=$1 rate=$2 size=$3 count=0
  if [ "$traffic" = yes ]; then
    # Ask the long-lived sender to flood; it replies "sent N" when finished and settled.
    printf 'FLOOD %s %s %s 4\n' "$rate" "$((DURATION + 4))" "$size" >&"${SENDER[1]}"
  fi
  local out; out=$(vm_ssh "$SAMPLER" 2>/dev/null) || out=
  if [ "$traffic" = yes ]; then read -r _ count <&"${SENDER[0]}" || count=0; fi
  if [ -z "$out" ]; then MEASURE_OUT=FAIL; return 0; fi
  MEASURE_OUT=$(python3 - "$out" "$count" <<'PY'
import sys
a,b,p0,p1=sys.argv[1].split("|")
f=lambda s:[int(x) for x in s.split()[1:]]
x,y=f(a),f(b)
tot=sum(y)-sum(x)
idle=(y[3]+y[4])-(x[3]+x[4])        # idle + iowait
print(tot-idle, tot, int(float(p1 or 0)-float(p0 or 0)), int(sys.argv[2] or 0))
PY
)
}

# (Bash closes coprocess descriptors in subshells and background jobs, so the sender is
# driven directly from the main shell and measure() returns its result in MEASURE_OUT.)
# One sender process keeps a single connection to the VM's NIC for the whole run.
# Reconnecting per run crashed QEMU 11.x under heavy load (see client.py --serve).
coproc SENDER { python3 "$HERE/vmtest/client.py" --serve --port "$VM_NET_PORT" --dst-mac "$VM_MAC_TEST" \
  --dst-ip "$VM_TEST_IP" --src-ip "$SRC"; }
read -r -u "${SENDER[0]}" ready_line; [ "$ready_line" = ready ] || die "sender did not start"
on_exit "printf 'QUIT\\n' >&${SENDER[1]} 2>/dev/null || true"

log "VM up ($VM_SMP vCPUs). Copying the binary."
vm_scp "$BR_DIR/bladerunner-linux-amd64" "/home/$VM_USER/"
vm_ssh "mv ~/bladerunner-linux-amd64 ~/bladerunner && chmod +x ~/bladerunner"
retry 30 1 vm_ssh 'true'

RES="$WORK/results.tsv"; : > "$RES"
IFS=, read -ra RATE_LIST <<<"$RATES"
IFS=, read -ra SIZE_LIST <<<"$SIZES"
log "settings: sizes ${SIZE_LIST[*]}, rates ${RATE_LIST[*]} pps (capped at ${MAX_GBPS} Gbit/s), $RUNS runs per mode, ${DURATION}s window, $VM_SMP vCPUs"

# frame_bytes SIZE: average Ethernet frame size (no FCS) for a payload size or "imix".
frame_bytes() {
  if [ "$1" = imix ]; then echo 358; else echo $(($1 + 42)); fi
}

for size in "${SIZE_LIST[@]}"; do
  fb=$(frame_bytes "$size"); cap=$(( $(python3 -c "print(int($MAX_GBPS*1e9/8))") / fb ))
  last=
  if [ -n "$GBPS" ]; then
    IFS=, read -ra G_LIST <<<"$GBPS"; WANTS=()
    for g in "${G_LIST[@]}"; do WANTS+=("$(python3 -c "print(int($g*1e9/8/$fb))")"); done
    cap=999999999
  else
    WANTS=("${RATE_LIST[@]}")
  fi
  for want in "${WANTS[@]}"; do
    rate=$(( want < cap ? want : cap )); rate=$(( rate / 10000 * 10000 ))
    [ "$rate" != "$last" ] || continue      # capped rates collapse into one stage
    last=$rate
    log "=== payload $size, offered load $rate pps (~$(python3 -c "print(round($rate*$fb*8/1e9,2))") Gbit/s) ==="
    for ((i=1; i<=RUNS; i++)); do
      if (( i % 2 )); then order="generic native"; else order="native generic"; fi
      for mode in $order; do
        start_daemon "$mode"
        measure no 0 "$size"; idle=$MEASURE_OUT     # same window with no traffic: the noise floor
        measure yes "$rate" "$size"; load=$MEASURE_OUT
        stop_daemon
        if [ "$load" = FAIL ] || [ "$idle" = FAIL ]; then
          echo "$size $rate $i $mode FAIL" >> "$RES"; warn "size $size rate $rate run $i $mode: guest unresponsive under load; excluded"
        else
          echo "$size $rate $i $mode $idle $load" >> "$RES"
          log "size $size rate $rate run $i $mode: idle[$idle] load[$load]"
        fi
      done
    done
  done
done

python3 - "$RES" "$DURATION" "${OUT:-}" "$RUNS" "$VM_SMP" <<'PY'
import sys, json, statistics as st
res, dur, out, runs, cpus = sys.argv[1], float(sys.argv[2]), sys.argv[3], sys.argv[4], sys.argv[5]
HZ = 100.0
def fbytes(size): return 358.0 if size == "imix" else int(size) + 42.0
data, fails, order = {}, {}, []
for l in open(res):
    f = l.split()
    size, rate, mode = f[0], int(f[1]), f[3]
    key = (size, rate)
    if key not in order: order.append(key)
    data.setdefault(key, {"generic": [], "native": []}); fails.setdefault(key, {"generic": 0, "native": 0})
    if f[4] == "FAIL":
        fails[key][mode] += 1; continue
    ib, it, ip, isent, lb, lt, lp, sent = map(int, f[4:])
    busy = max(lb - ib, 0)
    data[key][mode].append({"pps": lp / dur, "sent_pps": sent / (dur + 4),
                            "gbps": lp / dur * fbytes(size) * 8 / 1e9,
                            "delivered_pct": 100.0 * lp / max(sent * dur / (dur + 4), 1),
                            "cpu_pct": 100.0 * busy / lt if lt else 0.0,
                            "us_per_pkt": (busy * 1e6 / HZ / lp) if lp else float("nan")})
med = lambda rows, k: st.median(r[k] for r in rows)
print()
print("native (driver) vs generic XDP; every packet dropped; %s vCPUs; %gs window; %s runs per mode" % (cpus, dur, runs))
print("CPU %% is of all %s vCPUs, idle floor subtracted. Gbit/s counts frame data (no preamble or gap)." % cpus)
print("%-7s %-8s %-8s %5s %10s %11s %8s %8s %8s %20s" % ("payload", "offered", "mode", "runs", "sent pps", "XDP pps", "Gbit/s", "deliv", "CPU %", "CPU us/packet"))
summary = {}
for key in order:
    size, rate = key
    summary["%s@%d" % key] = {}
    for m in ("generic", "native"):
        rows = data[key][m]
        label = "%.2fM" % (rate / 1e6)
        if not rows:
            print("%-7s %-8s %-8s %5s  all %d runs failed: guest unresponsive (saturated)" % (size, label, m, "0", fails[key][m])); continue
        u = [r["us_per_pkt"] for r in rows]
        summary["%s@%d" % key][m] = {"runs": rows, "failed_runs": fails[key][m], "pps": med(rows, "pps"),
                                    "gbps": med(rows, "gbps"), "cpu_pct": med(rows, "cpu_pct"), "us_per_pkt": st.median(u)}
        note = "" if not fails[key][m] else "  (+%d unresponsive excluded)" % fails[key][m]
        print("%-7s %-8s %-8s %5d %10.0f %11.0f %8.2f %7.0f%% %8.1f %8.2f (%.2f-%.2f)%s" % (
            size, label, m, len(rows), med(rows, "sent_pps"), med(rows, "pps"), med(rows, "gbps"),
            med(rows, "delivered_pct"), med(rows, "cpu_pct"), st.median(u), min(u), max(u), note))
print()
for key in order:
    g, n = summary["%s@%d" % key].get("generic"), summary["%s@%d" % key].get("native")
    if g and n and g["us_per_pkt"] > 0:
        d = 100.0 * (g["us_per_pkt"] - n["us_per_pkt"]) / g["us_per_pkt"]
        summary["%s@%d" % key]["native_cpu_saving_pct"] = d
        print("payload %-5s %.2fM pps (%.1f Gbit/s): native costs %.0f%% less CPU per dropped packet" % (key[0], key[1] / 1e6, n["gbps"], d))
if out:
    json.dump(summary, open(out, "w"), indent=1); print("wrote", out)
PY
vm_stop
