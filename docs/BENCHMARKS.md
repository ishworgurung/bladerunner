# 🏎️ Native XDP and benchmarks

This page covers two related things: how to run bladerunner's tests with the
filter attached in **native** mode, and how the local benchmark compares native
mode against **generic** mode. Both run on your own machine in a virtual machine
(VM), with no root access and no special hardware.

## 1. Native versus generic mode, in plain English

XDP (eXpress Data Path) is the Linux hook that lets a program look at a network
packet before the rest of the kernel does. It can run in two places:

| Mode | Where the program runs | What it costs | Works on |
|---|---|---|---|
| **Native** (also called driver mode) | Inside the network card's driver, as the packet is first received | Lowest: the kernel has not yet built its per-packet buffer (an *skb*, "socket buffer") | Only drivers that support it |
| **Generic** (also called skb mode) | After the kernel has already built the skb | Higher: the buffer is allocated and then thrown away if the packet is dropped | Any network device |

For a DDoS filter that mostly drops packets, native mode matters because it avoids
that wasted work. Set the mode with `mode: native` or `mode: generic` in the YAML
config (or `--mode` on `bladerunner run`). See [ARCHITECTURE.md](ARCHITECTURE.md)
for where the program sits in the receive path.

## 2. Running the test suite in native mode

```sh
make vmtest-native            # x86-64 VM, program attached in native mode
```

This is the same test as `make vmtest` (see [OPERATIONS.md](OPERATIONS.md), "VM
tests"), with the daemon told `mode: native`. Beyond the usual checks it asserts
that the kernel really reports a **driver-mode** program: `ip -d link show test0`
prints an `xdp` flag on the interface line for native and `xdpgeneric` for generic.
Without that check, a silent fall-back to generic mode would go unnoticed.

Use x86-64 with KVM (hardware virtualization). The emulated aarch64 and riscv64
guests are too slow to be worth running in this mode.

### The virtual NIC settings

The VM's test network card is a `virtio-net` device (the standard paravirtual NIC).
For native XDP to attach to it, its offloads must be off, and the settings follow
the author's earlier write-up
[XDP/eBPF firewall in Rust](https://gctl.io/blog/2020/xdp-ebpf-firewall-in-rust/).
They are applied in `scripts/lib/vm.sh` when `--xdp-mode native` is used:

| Setting | Why |
|---|---|
| `csum=off`, `guest_csum=off` | No checksum offload: the driver refuses XDP while the guest expects the card to check checksums |
| `guest_tso4/tso6/ecn/ufo=off`, `host_tso4/tso6/ecn/ufo=off` | No segmentation or large-receive offload (TSO, "TCP segmentation offload"; UFO, UDP fragmentation offload): XDP programs see single packets of normal size |
| `mrg_rxbuf=off` | No mergeable receive buffers: each packet arrives in one buffer |
| `rx_queue_size=256`, `tx_queue_size=256` | The queue depth the write-up used |

**One difference from that write-up.** It asks for 2N queues for N virtual CPUs.
QEMU only offers more than one queue on its `tap` and `vhost` network backends,
which need root. This harness uses the rootless `stream` backend, so the NIC has a
single queue pair. That still works on the guest kernels used here (6.8 and 7.0):
newer kernels run the unused XDP transmit path in a slower locked mode instead of
refusing to attach. bladerunner only ever returns "pass" or "drop", so that path is
never used. Older kernels may refuse, which is why the 2N rule exists.

## 3. The benchmark

```sh
make dist                                   # build the binaries first
make vmbench                                # the full sweep below (about an hour)
make vmbench BENCH="--sizes imix --rates 1500000,3000000 --runs 6 --json out.json"
```

### What it measures

`scripts/vmbench.sh` boots one KVM VM (4 virtual CPUs) and, in every run, attaches the
program once in generic mode and once in native mode. The order alternates from run to
run, so slow drift (the host warming up, background load) does not favour one mode.

The host sends UDP packets from one blocklisted source address, so the filter drops
every packet. The only thing being compared is therefore the cost of **receiving and
dropping a packet**. Inside the guest, the script records:

* **CPU time** from `/proc/stat` over a fixed window, for all virtual CPUs;
* **packets seen** from the kernel's own drop counter (the `blocklist` reason in
  `bladerunner_packets_total`), so the per-packet cost uses packets that really
  reached XDP, not packets the host merely tried to send;
* an **idle baseline**: the same window with no traffic, subtracted as a noise floor.

The daemon runs with sampling, rate limiting, fingerprinting and heavy-hitter
blocking switched off, so nothing but the drop path is measured. Both modes use the
identical virtual NIC.

### Packet sizes

Small packets stress the packet rate; big packets stress the data rate. The sweep
covers both, because the answer differs:

| Payload | Ethernet frame | What it stands for |
|---|---|---|
| 60 bytes | 102 B | A small-packet flood (SYN, DNS or UDP floods) |
| 512 bytes | 554 B | Mid-size traffic |
| 1472 bytes | 1514 B | Full-size packets (a 1500-byte MTU, the largest ordinary frame) |
| `imix` | 60 / 590 / 1514 B, mixed 7 : 4 : 1 | The standard Internet mix (IMIX): mostly small packets with some medium and full-size ones |

Big packets cannot reach the packet rates small ones can, so the offered load is
capped at `--max-gbps` (default 10) of frame data, and each requested rate is lowered
to fit. Rates that become identical run only once.

### Options

| Option | Default | Meaning |
|---|---|---|
| `--sizes LIST` | `60,512,1472,imix` | UDP payload sizes in bytes, and/or `imix` |
| `--rates LIST` | `1500000,3000000,4000000,5000000,6000000` | Offered packets per second, run in this order |
| `--runs N` | 3 | Runs per mode at each stage |
| `--duration S` | 10 | Seconds in each measured window |
| `--cpus N` | 4 | Virtual CPUs in the VM |
| `--max-gbps G` | 10 | Cap on offered frame data, in Gbit/s |
| `--gbps LIST` | none | Offered loads in Gbit/s of frame data, instead of `--rates`; converted to packets per second for each size, and `--max-gbps` does not apply |
| `--json FILE` | none | Also write the results as JSON |
| `--keep`, `--work DIR` | off | Keep the working directory |

### Results

One x86-64 desktop with KVM, a 4-CPU guest, virtio-net, every packet dropped, 3 runs
per mode at each stage (medians). "Handled" is the share of the sent packets that
reached XDP: anything less means the guest could not keep up and the virtual NIC's
queue overflowed before the filter ever saw the packet. Raw numbers, including every
run, are in [benchmarks/native-vs-generic-2026-11-25.json](benchmarks/native-vs-generic-2026-11-25.json).

| Payload | Offered | Frame data | Generic handled | Native handled | Generic CPU per packet | Native CPU per packet | Native saving |
|---|---|---|---|---|---|---|---|
| 60 B | 1.5 M pps | 1.2 Gbit/s | 100% | 100% | 0.38 us | 0.19 us | 48% |
| 60 B | 3.0 M pps | 2.4 Gbit/s | 100% | 100% | 0.33 us | 0.18 us | 46% |
| 60 B | 4.0 M pps | 3.3 Gbit/s | **77%** | 100% | 0.32 us | 0.18 us | 45% |
| 60 B | 5.0 M pps | 4.1 Gbit/s | **60%** | 100% | 0.33 us | 0.17 us | 49% |
| 60 B | 6.0 M pps | 4.6 Gbit/s | **49%** | 100% (see note) | 0.34 us | 0.12 us | 63% |
| 512 B | 1.5 M pps | 6.7 Gbit/s | 100% | 100% | 0.36 us | 0.07 us | 80% |
| 512 B | 2.25 M pps | 10.0 Gbit/s | 100% | 100% | 0.35 us | 0.06 us | 82% |
| 1472 B | 0.82 M pps | 9.9 Gbit/s | 100% | 100% | 0.35 us | 0.09 us | 75% |
| IMIX | 1.5 M pps | 4.3 Gbit/s | 100% | 100% | 0.39 us | 0.14 us | 65% |
| IMIX | 3.0 M pps | 8.6 Gbit/s | **93%** | 100% | 0.35 us | 0.08 us | 77% |
| IMIX | 3.5 M pps | 10.0 Gbit/s | **81%** | 100% | 0.35 us | 0.08 us | 78% |

(M pps = million packets per second; us = microseconds. The 6 M pps row: the host
sender could only manage 5.65 M pps, and native handled all of it.)

**What it shows.**

1. **Native is cheaper per packet everywhere.** About 45 to 49% less CPU for small
   packets, and 65 to 82% less for larger and mixed traffic. Generic costs a
   near-constant 0.33 to 0.39 us per packet whatever the size.
2. **Generic hits a ceiling at about 3 million packets per second.** From 3 M pps up,
   one virtual CPU is fully busy (24.7% of the four) and every extra packet is lost
   before the filter sees it. In generic mode that ceiling is about 2.4 Gbit/s of
   small packets or 8 Gbit/s of IMIX traffic, per queue. Under a bigger flood, the
   filter would simply not get to look at the surplus.
3. **Native kept up everywhere that was tested.** At 5 M pps of small packets it used
   about 0.8 of a CPU, and at 10 Gbit/s of IMIX it used about 0.3. Its ceiling was
   not reached: the limit in the 6 M pps row was the host sender, not the guest.
4. **For a DDoS filter this matters most when it is under load.** Both modes give the
   same verdicts. The difference is how much traffic one core can judge before it
   starts missing packets, and how much CPU is left for everything else.

### Pushing past 10 Gbit/s

A second run raised the cap to 25 Gbit/s (`--gbps 15,20,25`, 512 B, 1472 B and IMIX,
same VM, 3 runs per mode). "Sent" is what the host actually managed to send: when it
falls below the offered rate, the host sender or QEMU was the limit, not the guest.
Raw numbers: [benchmarks/native-vs-generic-high-load-2026-11-25.json](benchmarks/native-vs-generic-high-load-2026-11-25.json).

| Payload | Offered | Mode | Sent | Handled by XDP | Frame data handled | Guest CPU | CPU per packet |
|---|---|---|---|---|---|---|---|
| 512 B | 15 Gbit/s (3.38 M pps) | generic | 3.24 M pps | 3.21 M pps | 14.2 Gbit/s | 25.1% | 0.31 us |
| 512 B | 15 Gbit/s | native | 3.38 M pps | 3.38 M pps | 15.0 Gbit/s | 3.9% | 0.04 us |
| 512 B | 20 Gbit/s (4.51 M pps) | generic | 3.23 M pps | 3.23 M pps | 14.3 Gbit/s | 25.1% | 0.31 us |
| 512 B | 20 Gbit/s | native | 4.03 M pps | 4.02 M pps | 17.8 Gbit/s | 2.7% | 0.02 us |
| 512 B | 25 Gbit/s (5.64 M pps) | generic | 3.22 M pps | 3.22 M pps | 14.3 Gbit/s | 25.1% | 0.31 us |
| 512 B | 25 Gbit/s | native | 4.04 M pps | 4.04 M pps | 17.9 Gbit/s | 3.5% | 0.03 us |
| 1472 B | 15 Gbit/s (1.23 M pps) | generic | 1.23 M pps | 1.23 M pps | 14.9 Gbit/s | 9.9% | 0.32 us |
| 1472 B | 15 Gbit/s | native | 1.23 M pps | 1.23 M pps | 14.9 Gbit/s | 1.5% | 0.04 us |
| 1472 B | 20 Gbit/s (1.65 M pps) | generic | 1.65 M pps | 1.65 M pps | 20.0 Gbit/s | 12.9% | 0.31 us |
| 1472 B | 20 Gbit/s | native | 1.65 M pps | 1.65 M pps | 20.0 Gbit/s | 2.3% | 0.05 us |
| 1472 B | 25 Gbit/s (2.06 M pps) | generic | 2.06 M pps | 2.06 M pps | 25.0 Gbit/s | 16.4% | 0.31 us |
| 1472 B | 25 Gbit/s | native | 2.06 M pps | 2.06 M pps | 25.0 Gbit/s | 2.9% | 0.05 us |
| IMIX | 15 Gbit/s (5.23 M pps) | generic | 4.36 M pps | 3.24 M pps (**74%**) | 9.3 Gbit/s | 25.3% | 0.31 us |
| IMIX | 15 Gbit/s | native | 4.84 M pps | 4.85 M pps | 13.9 Gbit/s | 2.8% | 0.02 us |
| IMIX | 20 Gbit/s (6.98 M pps) | generic | 4.39 M pps | 3.25 M pps (**74%**) | 9.3 Gbit/s | 25.1% | 0.31 us |
| IMIX | 20 Gbit/s | native | 4.80 M pps | 4.83 M pps | 13.8 Gbit/s | 2.7% | 0.02 us |
| IMIX | 25 Gbit/s (8.72 M pps) | generic | 4.42 M pps | 3.25 M pps (**73%**) | 9.3 Gbit/s | 25.3% | 0.31 us |
| IMIX | 25 Gbit/s | native | 4.80 M pps | 4.83 M pps | 13.8 Gbit/s | 3.3% | 0.02 us |

("Offered" is the target. "Frame data handled" is what actually reached XDP, so it
falls below the target wherever the sender or the guest could not keep up. Percentages
compare with what was sent.)

**What it shows.**

1. **Generic has a hard ceiling of about 3.2 million packets per second, whatever the
   packet size.** One virtual CPU is full (25% of four) and the cost is a constant 0.31
   us per packet. In Gbit/s that ceiling is 14.3 for 512-byte packets and 9.3 for
   IMIX. It is a packet-rate limit, not a data-rate limit: with 1472-byte packets the
   same ceiling is about 39 Gbit/s, so the test never reached it.
2. **Native used only 2 to 4% of the four CPUs everywhere.** It had far more room than
   the host could use. It kept up with everything the host sent, including
   25 Gbit/s of full-size packets.
3. **The harness, not the guest, stopped us.** The host sender (and QEMU's network
   backend) tops out at about 4 to 5 million packets per second, so native could only
   be pushed to 17.9 Gbit/s of 512-byte packets and 13.8 Gbit/s of IMIX. Full-size
   packets reached 25 Gbit/s because that takes only 2 M pps. So the limit is on
   packets per second, not bits per second.
4. **How generic fails differs by size.** With IMIX it loses packets before the filter
   (about a quarter dropped). With 512-byte packets the sender is slowed instead
   (it sent only 3.2 M of 3.4 to 5.6 M pps requested), because QEMU stops reading
   from the host once the guest falls behind. Either way, the guest cannot be
   handed more than about 3.2 M pps.

**Do not over-read the CPU numbers here.** At 0.02 to 0.05 us (20 to 50 nanoseconds)
per packet, native looks faster than I can explain for a program that does lookups
and updates counters on every packet, and the earlier 60-byte results showed 0.12 to
0.19 us at similar packet rates. The CPU clock comes from `/proc/stat` ticks, and
virtual-machine effects may be hiding some of it. The savings of 83 to 95% in this
table are probably too high. The conclusion that holds up is the throughput one:
generic stops at about 3.2 M pps and native does not.

### Limits: how far to trust it

* **It is a relative figure, not an absolute one.** virtio-net is a software driver, so
  this shows what skipping the buffer allocation and the generic hook is worth in
  that setting. A real NIC driver differs in both directions. Real-NIC numbers are
  still untested (see [STATUS.md](STATUS.md)).
* **Compare within a row, not across rows.** Native's per-packet cost varies from 0.02
  to 0.19 us between stages, and is lower for bigger packets even at the same packet
  rate. I do not have an explanation. Part of it may be virtual-machine overhead
  (interrupts and exits to the host), which is counted as guest CPU time and depends
  on the packet rate. Native and generic share the same VM and load within a row, so
  the saving in that row is a fair comparison.
* **The CPU clock is coarse.** `/proc/stat` counts in 10 millisecond ticks. That is fine
  at these loads (hundreds of ticks per run) but below roughly 200,000 packets per
  second the figure is mostly noise. A few single runs also show an odd low outlier
  (for example, a generic minimum of 0.07 us); the medians are unaffected.
* **One source, one queue.** One source address means one receive queue and one CPU.
  Real deployments spread traffic over several queues, which raises both ceilings.
  Sampling, rate limiting and attack detection are switched off here, and they add
  cost in a real deployment.
* **The harness tops out at about 4 to 5 million packets per second.** The host sender
  and QEMU's network backend set that limit. Native was never pushed to its own ceiling,
  so it only shows "at least this much".
* **KVM only.** On an emulated CPU the script would measure the emulator, so it
  refuses to run without KVM.

### A QEMU crash worth knowing about

Early runs of this benchmark crashed QEMU itself (version 11.1.2) under heavy load.
The core dump showed `qio_channel_create_watch` being called on a null connection
while QEMU flushed queued packets after the sender's connection had gone away. A
longer wait before disconnecting only postponed the crash. The sender
(`scripts/vmtest/client.py --serve`) now keeps one connection open for the whole
benchmark and takes its orders over a pipe, and the full sweep then ran without a
crash. If you see `qemu ... segfault` in `journalctl -k`, this is the first place to
look.

## 4. What would make this more convincing

The natural next steps, in order, are listed in [STATUS.md](STATUS.md) under "Not
tested": the same comparison on a real NIC driver (for example two cloud instances
with the ENA driver, or two physical machines), and a multi-queue run on a `tap`
backend, which needs root.

## 5. Files

| File | Role |
|---|---|
| `scripts/vmtest.sh` | The functional test; `--xdp-mode native` selects driver mode |
| `scripts/vmbench.sh` | The native-versus-generic benchmark |
| `scripts/lib/vm.sh` | Builds the VM and its NICs, including the native-mode settings |
| `scripts/vmtest/client.py` | Host-side packet sender used by both scripts; `--serve` keeps one connection open for the benchmark |
| `docs/benchmarks/` | Raw JSON results of the published runs |
