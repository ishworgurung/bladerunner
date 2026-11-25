# 🔧 Operations

## 🚦 Rollout

1. `mode: generic` or `native`, `dry_run: true`. Run for at least a few days of
   normal traffic. The baseline and fingerprint baseline learn from it.
2. `bladerunner status` / `/metrics`: look at `rate_limit`, `amp_port`, `invalid`,
   `fragment` counters. Anything non-zero is traffic that *would* be dropped.
   Investigate before enforcing.
3. Fill `allowlist` (management, monitoring, upstream, peers).
4. `bladerunner dryrun off`.

## 📊 Metrics

`bladerunner_packets_total{reason}`, `bladerunner_bytes_total{reason}`, `bladerunner_attack`,
`bladerunner_offered_pps`, `bladerunner_baseline_pps`, `bladerunner_fp_rules_active`,
`bladerunner_fp_rule_{matched,dropped}_packets_total{rule}`, `bladerunner_autoblocks_total`,
`bladerunner_samples_total`, `bladerunner_samples_lost_total` (non-zero = raise ring size or
`sample_rate`).

🚨 Alert on: `bladerunner_attack == 1`, `bladerunner_samples_lost_total` rate, `bladerunner_dry_run == 1`
in production.

## 🔌 Persist vs. fail-open

* default: XDP detaches when `bladerunner run` exits → **traffic flows unfiltered**.
* `--persist`: the program stays attached (link pinned) with the last config.
  An attack flag left on keeps the tight limits; TTL rules age out. Remove with
  `bladerunner detach`.

## 🔄 Reload

`SIGHUP` re-reads the YAML: limits, amp ports, detector settings and new
prefixes apply; **prefixes removed from the file are not removed** from the
maps (use `bladerunner unblock` / `bladerunner unallow`). Interface, mode and pin dir need a
restart.

## 🖧 NIC notes

* Native XDP needs driver support (`ethtool -i`). Mellanox mlx5, Intel
  i40e/ice/ixgbe, Broadcom bnxt, virtio-net, and ENA support it. Check
  queue count vs XDP: some drivers need queues ≤ half the max.
* LRO/GRO/jumbo frames can block native attach. Disable LRO.
* Pin RX IRQs / use RSS so per-CPU load is even; XDP runs in softirq on the
  RX queue's CPU.

## 🩺 Troubleshooting

| Symptom | Likely cause |
|---|---|
| `attach ... operation not supported` | driver lacks native XDP: use `--mode generic` to test |
| `verifier: ...` | kernel too old or a changed program; attach the log to an issue |
| `... exists: another instance` | previous `--persist` run: `bladerunner detach` |
| everything dropped after enforcing | allowlist missing; `bladerunner dryrun on` immediately |
| attack never detected | `detect.min_pps` above your real peak; check `bladerunner_offered_pps` |

## 🗄️ Shared lists from Redis (optional)

Several hosts can share one allow list and one block list through Redis. It is
**off by default** (`redis.enabled: false` in the YAML). The daemon only *reads*
Redis, on a timer, and copies what it finds into the kernel maps. Redis is never
consulted per packet, so it cannot slow the filter down.

**Data layout.** One Redis key per CIDR range, named `<key_prefix>:<list>:<cidr>`,
where `<list>` is `allow` or `block`. The value is free text (a reason, say).

```sh
redis-cli SET bladerunner:block:203.0.113.0/24 "port scanner" EX 3600   # blocked for an hour
redis-cli SET bladerunner:block:198.51.100.7   "bad host"               # permanent
redis-cli SET bladerunner:allow:10.1.2.0/24    "office"
redis-cli DEL bladerunner:block:203.0.113.0/24                          # lift the block
```

* The key's Redis TTL becomes the in-kernel TTL. A key with no TTL is permanent
  until you delete it. Deleting or expiring a key removes the range on the next poll.
* A bare address means /32 (IPv4) or /128 (IPv6). Host bits are masked off.
* The `protect` list stays YAML-only, because it switches a global filtering mode.

**Fail-open.** If Redis is down, slow or returns an error, the daemon changes
nothing: every entry already installed stays, and in-kernel TTLs keep running out
on their own. A sync reads both lists fully before it writes anything, so a failure
midway cannot leave a half-applied state. An outage is logged once (not every poll),
`bladerunner_redis_up` falls to 0, and the daemon starts normally even if Redis is
unreachable at boot. When Redis returns, the next poll applies its contents, which
is authoritative: entries it no longer has are withdrawn.

**Safety rails.**
* Block ranges broader than /8 (IPv4) or /16 (IPv6), including `0.0.0.0/0`, are
  refused and counted in `bladerunner_redis_invalid_keys_total`.
* Entries listed in the YAML are never removed, or shortened with a TTL, by the feed.
* `max_entries` caps each list (allow is also capped at 1000 by the kernel map).
* The allowlist still beats the blocklist in the data plane, and dry-run still
  applies to Redis-fed blocks.
* Anyone who can write to this Redis can drop traffic on every host that reads
  it. Use a private network, an ACL user (`username`), TLS (`tls`, `ca_file`) and a
  password, supplied through the environment variable named by `password_env` so the
  secret stays out of the YAML.

**Metrics:** `bladerunner_redis_up`, `_syncs_total`, `_sync_errors_total`,
`_invalid_keys_total`, `_truncated_total`, `_apply_errors_total`,
`_last_sync_timestamp_seconds` and `_entries{list}`. The connection settings
cannot be changed by SIGHUP; restart the daemon for those.

**Tests.** `go test ./internal/feed` starts a real Redis in Docker (or uses
`BLADERUNNER_TEST_REDIS=host:port`) and covers sync, TTLs, removal, bad keys, the
YAML guard and an outage with recovery. `scripts/vmtest.sh` repeats the main
scenarios with the real BPF maps in each VM, using a Redis on the host
(`--no-redis` skips it).

## 🖥️ VM tests (x86-64, aarch64, riscv64)

`scripts/vmtest.sh` boots a QEMU virtual machine for each target CPU, copies the
matching `bladerunner` binary onto it, attaches XDP to the VM's test network card and
drives traffic at it from the host, as if the host were a remote client. It
needs no root. CI runs the same script (the `vmtest` job in `ci.yml`).

```sh
make dist                       # cross-build dist/bladerunner-linux-{amd64,arm64,riscv64}
make vmtest                     # all three architectures
make vmtest VMARCH=x86_64      # one architecture
scripts/vmtest.sh --boot-only riscv64   # just check that a VM boots
make vmtest-native              # x86-64 with XDP in native (driver) mode
```

**Requirements:** `qemu-system-{x86_64,aarch64,riscv64}`, `qemu-img`,
`genisoimage` (or `mkisofs`/`xorriso`), `ssh`, `python3`, `curl`, and network
access to download the Ubuntu cloud images on first use (about 2 GB for all
three, cached in `~/.cache/bladerunner-vmtest`; each is checked against Ubuntu's
published SHA-256 sums). aarch64 needs UEFI firmware (`qemu-efi-aarch64`);
riscv64 needs `u-boot-qemu` or the EDK2 RISC-V firmware.

**Native (driver-mode) XDP.** `make vmtest-native` runs the same tests with the
program attached in native mode, and `make vmbench` compares native and generic mode
over several runs. Both are explained, with the NIC settings and the results, in
[BENCHMARKS.md](BENCHMARKS.md).

**How it works.** Each VM has two network cards:

* `mgmt0` uses QEMU's built-in user-mode networking with a forwarded SSH port.
  It is only for copying files and running commands, and XDP is never attached
  to it, so the control channel cannot be cut by the filter under test.
* `test0` is wired to a QEMU `stream` socket (a localhost TCP port). The host
  writes raw Ethernet frames to that socket (`scripts/vmtest/client.py`) and they
  arrive on `test0`, where bladerunner's XDP program is attached. This avoids
  TAP devices, bridges and `sudo`, and lets the client pick any source address,
  port and TTL.

Inside the VM a small receiver (`scripts/vmtest/rx.py`) counts the datagrams
that actually reach userspace. Anything XDP drops never arrives, so those counts
are the ground truth. The test checks that clean traffic is delivered, that a
blocklisted source, amplification-port traffic and a TTL-blocked source are
dropped, that the TTL block expires, that dry-run lets would-be drops through,
and that a baseline followed by a flood is detected and mitigated.

**Speed.** x86-64 uses KVM when the host is x86-64 and `/dev/kvm` is writable
(boots in about 30 seconds). aarch64 and riscv64 are fully emulated and take
minutes to boot, and the flood rate and detection thresholds are scaled down
automatically. Pass-direction checks allow a few lost frames; drop-direction
checks are exact.

**Limits.** The host is a client in the sense of being a separate sender, but it
injects frames directly rather than going through the host's own TCP/IP stack,
so this does not test routing, ARP or TCP behaviour. The default XDP mode is
`generic`; `--xdp-mode native` tries driver mode on the guest's virtio-net card
and is not covered by CI.

**Shared shell libraries** (`scripts/lib/`): `common.sh` (logging, dependency
checks, exit cleanup, assertions), `vm.sh` (image download and verification,
cloud-init seed, QEMU launch for each architecture, SSH helpers) and
`assert_summary.sh`.
