# 📋 Status and TODO

Last verified 2026-11-25 on a Linux 7.4 desktop (x86-64) with clang 23.1, Go 1.27.4 and
QEMU 11.1.2. The test VMs ran Ubuntu 24.04 (kernels 6.8 on x86-64 and aarch64, 7.0 on
riscv64). Items marked "not re-run" last passed on an earlier version of the code.

## ✅ Tested

| Check | Result |
|---|---|
| Static checks (`make lint`: `gofmt`, `go vet`, `staticcheck`, `shellcheck`, `actionlint`, `ruff`, `yamllint`; also a CI job) | Clean. `staticcheck` is run through `go run` at a pinned version, because a packaged binary built with an older Go fails on Go 1.27 code. `actionlint`, `ruff` and `yamllint` run when installed. `clang-tidy` only reports style noise on the BPF code. No Markdown linter is set up |
| Go unit tests (`go test -race ./...`: detector, fingerprinting, heavy hitters, config, metrics, Redis feed) | Pass, including with the race detector. The kernel-loading tests in `internal/bpf` skip without root, so this run does not cover them |
| Verifier accepts the XDP program | Yes, on the guest kernels 6.8 (x86-64, aarch64) and 7.0 (riscv64): the VM test loads and attaches it. The dedicated `TestVerifierComplexity` run is not re-run (needs root) |
| Kernel-side tests (verifier load + `BPF_PROG_TEST_RUN`, `make test`) | **Not re-run.** 11/11 passed earlier (block, allow, TTL expiry, dry-run, amplification ports, fragments, bad TCP flags, fingerprint rules, rate limits, IPv6, sampling), before the rename to `bladerunner`, the Redis feed and later changes. Needs root |
| Loopback end-to-end (XDP generic mode, 30s, `make e2e`) | **Not re-run** (needs root). Passed earlier: load went from a 739 pps baseline to 19,200 pps and was detected, two fingerprint rules were installed, the flooding source was blocked, clean traffic kept flowing |
| Cross-architecture VM test, generic mode (`make vmtest`: QEMU x86-64 with KVM, aarch64 and riscv64 emulated; XDP on a virtio-net NIC, host injects traffic) | x86-64: 20/20 checks pass (attach and attach-mode check, clean delivery, blocklist, amplification port, TTL block and expiry, dry-run, flood detection with fingerprint rule and auto-block, and the Redis phase). aarch64 and riscv64: 10/10 passed before the Redis phase and the attach-mode check were added; **not re-run** since |
| Native (driver-mode) XDP on virtio-net (`make vmtest-native`, x86-64 with KVM) | 20/20 checks pass, including the check that the kernel lists the program as driver mode. Single queue pair; multi-queue (tap/vhost) and real NIC drivers are not tested |
| systemd unit (`bladerunner systemd`, `--last-good`, `Type=notify`; `go test ./cmd/...`, `make vmtest` phase 6) | Pass: unit text and unsafe-value refusal, `systemd-analyze verify` (host and guest), last-good save, atomic write and fallback logic, notify and interface-wait helpers. In the x86-64 VM with real systemd: start returns only after XDP attaches, ordering before `network-pre.target`, filtering, a broken config falls back to the last good copy, restart after `kill -9`, stop detaches XDP. Not run on aarch64 and riscv64; no reboot test |
| Redis list feed (`go test ./internal/feed`, real Redis in Docker; `make vmtest` phase) | Pass: sync, TTL carry-over, key deletion and expiry, invalid and too-broad ranges refused, YAML entries protected, entry cap, outage keeps all entries (fail-open) and recovery. In the x86-64 VM with real BPF maps: block and allow from Redis take effect, allow beats a YAML block, the block still holds while Redis is down. Not run on aarch64 and riscv64 |
| Native vs generic XDP cost (`make vmbench`, x86-64 KVM, 4 vCPUs, virtio-net, drop path only; 60 B, 512 B, 1472 B and IMIX packets, up to 25 Gbit/s, 3 runs per mode) | Native used 45 to 49% less CPU per dropped packet for small packets and 65 to 82% less for larger and mixed ones (higher still past 10 Gbit/s, but those figures are probably too high). Generic saturated one CPU at about 3.2 M pps for every packet size (14 Gbit/s at 512 B, 9 Gbit/s of IMIX) and lost packets or slowed the sender; native used 2 to 4% of the CPUs and kept up with everything the host could send (25 Gbit/s of 1472 B, 17.9 of 512 B, 13.8 of IMIX; the host sender caps at 4 to 5 M pps). Relative figures on a software NIC. Details: [BENCHMARKS.md](BENCHMARKS.md) |
| Genuine web requests during the flood (`make vmbench BENCH="--http ..."`, 512 KiB page at 50 requests/s through the same virtual NIC, 512 B, 1472 B and IMIX floods at 10 to 25 Gbit/s offered, 3 runs per mode) | With generic mode, past its ceiling of about 3.1 M pps, requests wait seconds (TTFB p99 0.6 to 3 s), 55 of 1500 fail at 512 B and 540 of 1500 at IMIX 10 Gbit/s, and in the heavier IMIX stages all of them fail. With native mode, none of 18,000 requests failed; p99 TTFB was 1 to 54 ms (one stage 486 ms). Below the generic ceiling (full-size packets) the two modes are the same. Native's 36 to 45 ms at the heaviest stages is mostly harness queueing. Details and caveats: [BENCHMARKS.md](BENCHMARKS.md) |

## 🧪 Not tested (TODO)

- [ ] **GitHub Actions.** Actions is disabled for the repository and the workflows (`ci`, `build`, `cleanup`) have never run in their current form. That includes the `vmtest` job and its native x86-64 entry. Re-enable, run them, and fix what breaks (package names, KVM setup, run time, artifact storage quota).
- [ ] **Root tests after the many changes.** Re-run `make test` and `make e2e` (they need root). The eBPF license string is still `"Dual BSD/GPL"` and has not been tried with other values.
- [ ] **aarch64 and riscv64 VM runs** with the Redis phase and the attach-mode check.
- [ ] **Real NIC drivers.** Native mode and the benchmark have only been run on virtio-net. Candidates: two EC2 instances with the ENA driver, or two physical machines with Intel or Mellanox NICs.
- [ ] **Multi-queue.** Needs a tap or vhost backend (root), or real hardware. Every run so far used one queue and one CPU.
- [ ] **Throughput past the test harness.** The host sender and QEMU top out at about 4 to 5 M pps, so native's own ceiling was never reached.
- [ ] **Kernels older than ~5.15.** Native attach on virtio-net also needs a kernel that tolerates a single queue pair (the tested 6.8 and 7.0 do).
- [ ] **Soak run in dry-run on production traffic** for a few days.

## 🛠️ Future work

- [ ] **CIDR blocklist feeds.** Pull public IP blocklists (for example Spamhaus DROP or FireHOL-style lists) into the block set, from a file or URL, with the same safety rails as the Redis feed (no ranges broader than /8 or /16, entries from the YAML never removed, fail-open if the source is unreachable). Highest value for the least work.
- [ ] **Address matching in rules.** Rules have no source or destination address today. Options: a prefix field per rule, or a lookup into the existing allow/block/protect sets. A prerequisite for importing rules from any outside source.
- [ ] **Snort rule import (low priority).** Probably not worth building in general. Snort rules mostly match payload content, which the header-only data plane cannot see, so an import would skip most of any ruleset, and Snort's address scoping, direction and flow state do not map onto our rules. The one case worth revisiting is a narrow import of DDoS-specific rulesets (for example Emerging Threats' DoS category), which describe reflection and amplification patterns by header and size. It would map header, port, `dsize`, `flags` and `ttl` onto fingerprint rules and report every rule it skipped. Needs address matching first, and overlaps with the existing amplification-port table.
- [ ] **Fixed-offset payload match (only if needed).** Extend `bladerunner_fp_rule` and the XDP program with a short byte match at a fixed offset. Needs verifier work and a re-check against `TestVerifierComplexity`. Most Snort `content` rules match anywhere in the payload, so this would cover few of them. Do it only if header-only fingerprints prove too blunt on real traffic.
- [ ] **More than 32 fingerprint rules.** Needed if imported rule sets grow. The linear scan will not scale; consider a hash or per-protocol index.
- [ ] **Per-file license headers** on the Go sources (the repo is MIT via the root `LICENSE`, but only the BPF files carry an SPDX line).
- [ ] **Toolchain pin.** `go.mod` says `go 1.27`. A `GOROOT` environment variable pointing at 1.27.1 while `go` was 1.27.4 broke local builds. Add a `toolchain` line and document the supported version.
- [ ] **IPv6 extension headers** beyond Fragment (see Known limits).
- [ ] **Shadow rules.** Per-rule "count but do not drop" state, so a new fingerprint rule is observed before it enforces (see [DESIGN.md](DESIGN.md) section 12.1).
- [ ] **Approval mode.** Detector candidates and imported rules wait for `bladerunner rules approve <id>`; auto-approve stays the default.
- [ ] **Rule effectiveness feedback.** Retire rules that match nothing and roll back rules that hurt known-good traffic.
- [ ] **Hash-chained audit log** of every rule, block and config change.
- [ ] **Least-privilege run mode.** Document and test running as a non-root user with `CAP_BPF`, `CAP_NET_ADMIN`, `CAP_PERFMON`; restrict the pin directory.
- [ ] **Signed rule bundles** that the daemon verifies before loading.
- [ ] **Boot-time unit: verify at a real boot.** The unit and its last-known-good fallback are built and tested; what remains is enabling it in a VM, rebooting, and checking from `systemd-analyze critical-chain` and the interface that the filter attaches before the network target. Also decide whether to add a `--persist` variant.
- [ ] **SPDX SBOM** attached to each release archive; optional OpenTelemetry export.
- [ ] **Redis extras.** Feed the `protect` list from Redis, publish this host's auto-blocks back, and use Redis pub/sub so changes apply instantly instead of at the next poll. Signed entries would remove the trust risk of a shared Redis.

## ⚠️ Known limits

- **NIC offload is not supported.** "Native" means driver-mode XDP on the host CPU. The program uses LPM tries, LRU and per-CPU maps and a ring buffer, which offload drivers are generally not expected to support (not verified against current driver documentation).
- **The VM benchmark depends on QEMU's stream backend.** QEMU 11.1.2 crashes (a null channel in `qio_channel_create_watch`) when the sender's connection is closed while packets are queued, so the benchmark holds one connection open for the whole run. See [BENCHMARKS.md](BENCHMARKS.md).
- **Rate limiting is approximate.** A few percent error under multi-queue load (no cross-CPU atomics).
- **Spoofed floods.** Per-source blocking can hit innocent addresses (TTL-bounded). Fingerprint rules are the better tool there.
- **Fingerprint rules can false-positive** on new legitimate traffic during an attack; mitigated by attack-only, baseline-absent, TTL and dry-run.
- **IPv6:** only the Fragment extension header is parsed.
- **SIGHUP reload** adds prefixes but never removes them. Changes to the `redis:` section need a restart.
- **Redis feed** covers the allow and block lists only, and a Redis outage keeps the last known entries rather than clearing them.

## 🚀 Run it

```sh
git clone git@github.com:ishworgurung/bladerunner && cd bladerunner
sudo apt install clang libbpf-dev linux-libc-dev golang
make deps && make build && make test
cp configs/bladerunner.yaml my.yaml    # set interface, protected, allowlist
sudo ./bladerunner run -c my.yaml               # starts in dry-run, nothing is dropped
sudo ./bladerunner status                       # shows what would be dropped
sudo ./bladerunner dryrun off                   # enforce
```

🔑 Put management and upstream addresses in `allowlist` before turning dry-run off.
