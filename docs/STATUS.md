# 📋 Status and TODO

Last verified: Linux 6.18, clang 18.

## ✅ Tested

| Check | Result |
|---|---|
| Verifier accepts the XDP program | Yes |
| Kernel-side tests (verifier load + `BPF_PROG_TEST_RUN`) | 11/11 pass: block, allow, TTL expiry, dry-run, amplification ports, fragments, bad TCP flags, fingerprint rules, rate limits, IPv6, sampling |
| Go unit tests (detector, fingerprinting, heavy hitters, config, metrics) | Pass, including with the race detector |
| Loopback end-to-end (XDP generic mode, 30s, `make e2e`) | Pass. Load went from a 739 pps baseline to 19,200 pps and was detected. Two fingerprint rules were installed, the flooding source was blocked, clean traffic kept flowing |
| Redis list feed (`go test ./internal/feed`, real Redis in Docker; `make vmtest` phase 5) | Pass: sync, TTL carry-over, key deletion and expiry, invalid and too-broad ranges refused, YAML entries protected, entry cap, outage keeps all entries (fail-open) and recovery. In the x86-64 VM with real BPF maps: block and allow from Redis take effect, allow beats a YAML block, the block still holds while Redis is down. Not yet run on aarch64 and riscv64 |
| Cross-architecture VM test (`make vmtest`: QEMU x86-64 with KVM, aarch64 and riscv64 emulated; Ubuntu 24.04; XDP generic mode on a virtio-net NIC, host injects traffic) | 10/10 checks pass on each: daemon attach, clean delivery, blocklist, amplification port, TTL block and expiry, dry-run, flood detection with fingerprint rule and auto-block. Kernels 6.8 (x86-64, aarch64) and 7.0 (riscv64). The CI `vmtest` job has not run on GitHub yet |
| Native (driver-mode) XDP on virtio-net (`make vmtest-native`, x86-64 with KVM) | 20/20 checks pass, including the check that the kernel lists the program as driver mode. Single queue pair; multi-queue (tap/vhost) and real NIC drivers are not tested |
| Native vs generic XDP cost (`make vmbench`, x86-64 KVM, 4 vCPUs, virtio-net, drop path only; 60 B, 512 B, 1472 B and IMIX packets, 0.8 to 6 M pps, 3 runs per mode) | Native used 45 to 49% less CPU per dropped packet for small packets and 65 to 82% less for larger and mixed ones. Generic saturated one CPU at about 3 M pps and lost packets before the filter (49 to 93% handled above that); native handled everything offered, up to 5.6 M pps of small packets and 10 Gbit/s of IMIX. Pushed to 25 Gbit/s: generic is capped at about 3.2 M pps for every packet size (14 Gbit/s at 512 B, 9 Gbit/s of IMIX); native used 2 to 4% of the CPUs and kept up with everything the host could send (up to 25 Gbit/s of 1472 B, 17.9 of 512 B, 13.8 of IMIX; the host sender caps at 4 to 5 M pps). Relative figures on a software NIC; not measured on real hardware. Details: [BENCHMARKS.md](BENCHMARKS.md) |

## 🧪 Not tested (TODO)

- [ ] Native (driver) mode: the VM test uses generic mode; `--xdp-mode native` on virtio-net and on a real NIC are untested.
- [ ] Throughput: no Mpps numbers, no multi-queue testing.
- [ ] Kernels older than ~5.15.
- [ ] Soak run in dry-run on production traffic for a few days.
- [ ] Re-run the root kernel tests (`make test`) after the license change. The eBPF license string is still `"Dual BSD/GPL"` and has not been tried with other values.

## 🛠️ Future work

- [ ] **Snort rule import (header-only subset).** Add a command such as `bladerunner rules load snort.rules` that maps protocol, ports, `dsize`, `flags` and `ttl` onto fingerprint rules and reports every rule it skipped, with the reason. No data-plane change needed.
- [ ] **Fixed-offset payload match.** Extend `bladerunner_fp_rule` and the XDP program with a short byte match at a fixed offset (Snort `content` with `offset`/`depth`). Needs verifier work and a re-check against `TestVerifierComplexity`. Worth doing only if header-only rules prove too blunt on real traffic.
- [ ] **Address matching in rules.** Rules have no source or destination address today, so imported rules lose their address scope. Options: a prefix field per rule, or a lookup into the existing allow/block/protect sets.
- [ ] **More than 32 fingerprint rules.** Needed if imported rule sets grow. The linear scan will not scale; consider a hash or per-protocol index.
- [ ] **Per-file license headers** on the Go sources (the repo is MIT via the root `LICENSE`, but only the BPF files carry an SPDX line).
- [ ] **Toolchain pin.** `go.mod` says `go 1.27` while the installed Go tools disagree (`go1.27.1` vs `go1.27.4`), which breaks `go build` locally. Settle on a version and document it.
- [ ] **IPv6 extension headers** beyond Fragment (see Known limits).
- [ ] **Shadow rules.** Per-rule "count but do not drop" state, so a new fingerprint rule is observed before it enforces (see [DESIGN.md](DESIGN.md) section 12.1).
- [ ] **Approval mode.** Detector candidates and imported rules wait for `bladerunner rules approve <id>`; auto-approve stays the default.
- [ ] **Rule effectiveness feedback.** Retire rules that match nothing and roll back rules that hurt known-good traffic.
- [ ] **Hash-chained audit log** of every rule, block and config change.
- [ ] **Least-privilege run mode.** Document and test running as a non-root user with `CAP_BPF`, `CAP_NET_ADMIN`, `CAP_PERFMON`; restrict the pin directory.
- [ ] **Signed rule bundles** that the daemon verifies before loading.
- [ ] **Boot-time unit.** systemd unit that attaches the last known-good config before the network is up.
- [ ] **SPDX SBOM** attached to each release archive; optional OpenTelemetry export.
- [ ] **Redis extras.** Feed the `protect` list from Redis, publish this host's auto-blocks back, and use Redis pub/sub so changes apply instantly instead of at the next poll. Signed entries would remove the trust risk of a shared Redis.

## ⚠️ Known limits

- **NIC offload is not supported.** "Native" means driver-mode XDP on the host CPU.
- **`go.sum` is not committed.** The Go module proxy was blocked in the build sandbox, which used Ubuntu's packaged cilium/ebpf 0.11.0 (old). Run `make deps` once, then bump the version if wanted.
- **Rate limiting is approximate.** A few percent error under multi-queue load (no cross-CPU atomics).
- **Spoofed floods.** Per-source blocking can hit innocent addresses (TTL-bounded). Fingerprint rules are the better tool there.
- **Fingerprint rules can false-positive** on new legitimate traffic during an attack; mitigated by attack-only, baseline-absent, TTL and dry-run.
- **IPv6:** only the Fragment extension header is parsed.
- **SIGHUP reload** adds prefixes but never removes them.

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
