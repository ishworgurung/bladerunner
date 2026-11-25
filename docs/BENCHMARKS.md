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
| `--http` | off | While the flood runs, fetch a 512 KiB page from a web server in the VM through the same virtual NIC (see "Genuine web requests during the flood") |
| `--http-rate N` | 50 | Web requests per second for `--http` |
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

### Genuine web requests during the flood

Packet counters say how the filter copes. They do not say what a real user sees. So
`--http` also makes genuine web requests **while the flood is running**, through the
same virtual NIC and the same XDP hook, and measures them.

**How.** A small web server in the VM (`scripts/vmtest/httpd.py`) returns a 512 KiB body
for every request. The host has no network stack on the test link, so the sender
(`scripts/vmtest/httpload.py`) carries a minimal ARP, TCP and HTTP client of its own: it
opens a connection, sends one `GET`, acknowledges the reply, retransmits its own lost
packets, and records the **connect time**, the **time to first byte (TTFB)** and the
**total time**. TTFB is counted from the start of the connection, as `curl` does. Requests
start at a **fixed rate** (50 per second, one every 20 ms) whether or not earlier ones
finished, so a slow server cannot hide its latency by receiving fewer requests. The
requests use their own source address, which is not on the blocklist, so the filter passes
them. They start two seconds into each measured window and run for the whole window, with
the flood at full strength. The same requests also run in the same VM and mode with **no
flood**, as the baseline. Results are pooled over the 3 runs (1500 requests per row).

**Results** (x86-64 KVM, 4 vCPUs, 3 runs per mode, 1500 requests per cell; times in
milliseconds; "failed" counts requests that were reset, timed out after 8 s or came back
incomplete). With no flood, every row had TTFB p50 0.5 ms and p99 about 0.9 ms, so that is
the baseline. Raw numbers: [benchmarks/http-under-flood-2026-11-25.json](benchmarks/http-under-flood-2026-11-25.json).

| Payload | Offered | Generic: failed | TTFB p50 | TTFB p99 | total p99 | Native: failed | TTFB p50 | TTFB p99 | total p99 |
|---|---|---|---|---|---|---|---|---|---|
| 512 B | 10 Gbit/s | 0 | 0.7 | 1.1 | 6.6 | 0 | 0.5 | 3.1 | 11.4 |
| 512 B | 15 Gbit/s | 2 | **224** | **572** | **3,020** | 0 | 0.7 | 15.6 | 35.2 |
| 512 B | 20 Gbit/s | **55** | **1,174** | **2,595** | **7,905** | 0 | 36.1 | 39.3 | 133.8 |
| 512 B | 25 Gbit/s | 4 | **1,136** | **1,921** | **6,575** | 0 | 36.1 | 49.2 | 202.5 |
| 1472 B | 10 Gbit/s | 0 | 0.5 | 1.0 | 4.2 | 0 | 0.6 | 1.1 | 4.6 |
| 1472 B | 15 Gbit/s | 0 | 0.5 | 1.2 | 5.3 | 0 | 0.6 | 1.1 | 5.5 |
| 1472 B | 20 Gbit/s | 0 | 0.6 | 4.1 | 10.3 | 0 | 0.6 | 6.5 | 13.8 |
| 1472 B | 25 Gbit/s | 0 | 0.6 | 7.7 | 21.3 | 0 | 0.5 | 8.1 | 19.7 |
| IMIX | 10 Gbit/s | **540 (36%)** | **2,163** | **3,018** | **7,974** | 0 | 0.6 | 8.6 | 21.9 |
| IMIX | 15 Gbit/s | **1500 (100%)** | n/a | n/a | n/a | 0 | 44.4 | 54.3 | 172.4 |
| IMIX | 20 Gbit/s | **1500 (100%)** | n/a | n/a | n/a | 0 | 44.7 | 486.3 | 609.0 |
| IMIX | 25 Gbit/s | **1500 (100%)** | n/a | n/a | n/a | 0 | 44.8 | 53.5 | 176.0 |

("Offered" is the target. The host could not send more than about 4 to 5 million packets
per second, so above that the delivered load was lower: at most about 17.9 Gbit/s of 512 B
and 13.8 Gbit/s of IMIX. Generic handled about 3.1 million packets per second at most.)

**What it shows.**

1. **Generic mode takes the service down once the flood passes its ceiling.** Past about
   3.1 million packets per second, real requests wait seconds for the first byte, 55 of 1500
   fail at 512 B and 540 of 1500 (36%) at IMIX 10 Gbit/s, and in the heavier IMIX stages
   every single request fails. The filter
   is dropping the attack, but the guest has no CPU left to receive the legitimate packets
   before the filter ever runs, so they are lost with the flood.
2. **Native mode kept the service up in every stage.** Not one request failed in 18,000
   (12 rows by 1500). Tail latency still rose, to tens of milliseconds, but the page
   always loaded.
3. **Below the generic ceiling the two modes are the same.** With full-size packets the
   flood is only about 1 to 2 million packets per second, which generic handles, so both
   modes showed a few milliseconds of extra tail latency at 20 and 25 Gbit/s and nothing
   else. A volumetric flood of big packets is not what separates them; a flood of many
   packets is.
4. **For an operator:** with generic mode, the attack succeeds as a denial of service on
   everything else on that interface, even though the filter is "working". Native mode is
   what lets the filter protect a service.

**Read the absolute numbers with care.**

* **The 36 to 45 ms in native's TTFB at the heaviest stages is mostly the harness.** The
  sender and QEMU's network backend saturate at about 4 to 5 million packets per second, so
  the request packets queue behind the flood in the test link. The value is nearly constant
  (36 ms, then 44 ms) across offered loads above that point, which fits a full queue of
  fixed size rather than a guest that is overloaded. Queueing behind an attack in one shared
  queue is realistic; the size of that queue is not. Treat these figures as "tens of
  milliseconds, not seconds".
* **Some baseline rows are contaminated.** The no-flood baseline for generic at IMIX 20 and
  25 Gbit/s shows a p99 of 450 to 1,040 ms. It runs right after a stage whose flood left a
  backlog in the test link, which had not finished draining. Every other baseline is about
  1 ms.
* **Occasional spikes.** One native cell (IMIX at 20 Gbit/s) has a p99 of 486 ms against
  about 54 ms in its neighbours; with 1500 requests, a few slow ones decide the p99.
* **The client shares a Python process with the flood sender**, so it adds a small floor
  (about 0.5 ms of TTFB in the baseline) and some jitter. That is why the comparison is with
  the baseline, not with zero.
* **The CPU-per-packet figures in this run are not comparable to the earlier run.** The
  web server's own CPU is included, and the flood is sent in small pieces (so the requests
  interleave with it) instead of 10 ms bursts. Use the earlier no-HTTP sweep for CPU cost.
* **One request pattern and one page size** (50 requests per second, 512 KiB). A busier
  site, bigger pages, TLS or several virtual hosts would change the numbers. The qualitative
  result (a saturated generic receive path starves legitimate traffic) should not.

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
| `scripts/vmtest/client.py` | Host-side packet sender used by both scripts; `--serve` keeps one connection open for the benchmark and runs flood and web-request commands at the same time |
| `scripts/vmtest/httpload.py` | The small ARP, TCP and HTTP client that fetches pages through the test NIC during the flood |
| `scripts/vmtest/httpd.py` | The web server in the VM that returns a 512 KiB body |
| `docs/benchmarks/` | Raw JSON results of the published runs |
