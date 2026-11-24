// SPDX-License-Identifier: MIT
/*
 * bladerunner XDP data plane.
 *
 * Order of evaluation (first match wins):
 *   parse -> allowlist -> ND exemption -> protected-set -> blocklist ->
 *   sanity -> fragments -> amplification ports -> fingerprint rules ->
 *   per-source token buckets -> pass
 *
 * Fail-open: a missing config passes everything. Every dropping decision is
 * suppressed (but still counted) in dry-run mode.
 */
// Only stable kernel UAPI headers and libbpf's helper headers are used (no
// vmlinux.h / CO-RE): we only read well-known packet-format structs, so there is
// nothing kernel-version-specific to relocate. This keeps the build dependency
// down to clang + libbpf-dev + linux-libc-dev.
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "bladerunner_common.h"

// This string is read by the kernel at load time; it is NOT the license of this
// source (see LICENSE). The kernel only lets a program call GPL-only helpers if
// the string is GPL-compatible, so it is kept as "Dual BSD/GPL". Do not change
// it without re-running the root kernel tests (make test) on the target kernel.
char LICENSE[] SEC("license") = "Dual BSD/GPL";

// Some libc/UAPI header sets omit the 802.1ad (QinQ) ethertype; define it here.
#ifndef ETH_P_8021AD
#define ETH_P_8021AD 0x88A8
#endif
// IPv4 frag_off field (host order after ntohs): bit 0x2000 = "more fragments",
// low 13 bits = fragment offset in 8-byte units. offset != 0 means a later
// fragment; MF set with offset 0 means the first fragment.
#define IP_MF_OFF 0x2000
#define IP_OFFMASK 0x1FFF
// TCP flag bits as they appear in byte 13 of the TCP header.
#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_ACK 0x10

/* ------------------------------------------------------------------ maps */

// cfg: the single runtime configuration entry (key 0). Written by the control
// plane, read once per packet. ARRAY maps are preallocated and lookups never
// fail for an in-range key, but we still NULL-check to satisfy the verifier.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct bladerunner_config);
} cfg SEC(".maps");

// stats: one slot per verdict reason (plus the sampling counters). PERCPU so the
// hot path increments a CPU-local counter with no atomics and no cache-line
// bouncing; userspace sums the per-CPU copies when it reads.
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, BLADERUNNER_NSTAT);
	__type(key, __u32);
	__type(value, struct bladerunner_counter);
} stats SEC(".maps");

// LPM (longest-prefix-match) trie definitions. BPF_F_NO_PREALLOC is mandatory
// for LPM tries; nodes are allocated on insert. Keys are bladerunner_lpm4_key /
// bladerunner_lpm6_key; values carry an optional in-kernel expiry (bladerunner_lpm_val).
#define LPM4(name, n)                                                 \
	struct {                                                      \
		__uint(type, BPF_MAP_TYPE_LPM_TRIE);                  \
		__uint(max_entries, n);                               \
		__uint(map_flags, BPF_F_NO_PREALLOC);                 \
		__type(key, struct bladerunner_lpm4_key);                      \
		__type(value, struct bladerunner_lpm_val);                     \
	} name SEC(".maps")

#define LPM6(name, n)                                                 \
	struct {                                                      \
		__uint(type, BPF_MAP_TYPE_LPM_TRIE);                  \
		__uint(max_entries, n);                               \
		__uint(map_flags, BPF_F_NO_PREALLOC);                 \
		__type(key, struct bladerunner_lpm6_key);                      \
		__type(value, struct bladerunner_lpm_val);                     \
	} name SEC(".maps")

// The six prefix sets. allow* = sources that are never filtered (checked first,
// so it always beats block*). block* = sources that are always dropped.
// protect* = destination prefixes to defend when BLADERUNNER_F_PROTECTED_ONLY is set.
// Capacities: IPv4 blocklist 262,144 and IPv6 65,536 entries (see docs).
LPM4(allow4, 1024);
LPM6(allow6, 1024);
LPM4(block4, 262144);
LPM6(block6, 65536);
LPM4(protect4, 1024);
LPM6(protect6, 1024);

// amp_ports: UDP source port -> bladerunner_amp. A small HASH (<=256 entries) because the
// key space is sparse (a handful of well-known reflector ports).
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 256);
	__type(key, __u16);
	__type(value, struct bladerunner_amp);
} amp_ports SEC(".maps");

// fp_rules: the fingerprint rule table, scanned linearly (<= BLADERUNNER_MAX_FP_RULES).
// ARRAY so slot i is addressable by index; unused slots have action NONE.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, BLADERUNNER_MAX_FP_RULES);
	__type(key, __u32);
	__type(value, struct bladerunner_fp_rule);
} fp_rules SEC(".maps");

// fp_counters: per-rule match/drop counters, per-CPU for lock-free updates.
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, BLADERUNNER_MAX_FP_RULES);
	__type(key, __u32);
	__type(value, struct bladerunner_fp_counter);
} fp_counters SEC(".maps");

// fp_buckets: the SHARED token bucket for each BLADERUNNER_FP_RATELIMIT rule (index == rule
// slot). Not per-CPU: all CPUs draw from one bucket so the limit is global.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, BLADERUNNER_MAX_FP_RULES);
	__type(key, __u32);
	__type(value, struct bladerunner_bucket);
} fp_buckets SEC(".maps");

// rl4: per-(IPv4 source, class) token buckets. LRU_HASH so the table can never
// fill up under a spoofed-source flood: the least recently used entries are
// evicted automatically instead of new sources failing to insert.
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 262144);
	__type(key, struct bladerunner_rl4_key);
	__type(value, struct bladerunner_bucket);
} rl4 SEC(".maps");

// rl6: same as rl4 for IPv6, keyed on the first 64 bits (a /64 is one subscriber).
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 131072);
	__type(key, struct bladerunner_rl6_key);
	__type(value, struct bladerunner_bucket);
} rl6 SEC(".maps");

// samples: ring buffer feeding the control plane (single shared buffer, 4 MiB).
// Chosen over perf buffers because it is shared across CPUs, preserves ordering
// and wastes no per-CPU memory.
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 22); /* 4 MiB */
} samples SEC(".maps");

/* ---------------------------------------------------------------- packet */

// Parsed view of one packet. Everything the filter stages need is extracted
// once, up front, so later stages never touch packet memory (which keeps the
// verifier's bounds-checking burden confined to parse()).
// IPv4 addresses occupy saddr[0]/daddr[0] only; IPv6 uses all four words. The
// words hold the raw network-order bytes (not byte-swapped).
struct pkt {
	__u32 saddr[4];
	__u32 daddr[4];
	__u16 sport, dport; /* host order, 0 when no L4 header was seen */
	__u16 l3len;
	__u8 family, proto, ttl, tcp_flags;
	__u8 icmp_type, frag; /* frag: 0 none, 1 first fragment, 2 later */
};

// Parse outcomes: OK, not an IP packet (leave alone), or malformed (drop).
enum { PARSE_OK = 0, PARSE_NONIP = 1, PARSE_BAD = 2 };

// Parse the transport header at `l4` into p. Returns PARSE_BAD only when the
// header is truncated. Every pointer dereference is preceded by a comparison
// against data_end: that is what the verifier needs to prove the access safe.
static __always_inline int parse_l4(struct pkt *p, void *l4, void *end)
{
	switch (p->proto) {
	// TCP: ports, and the flags byte (offset 13; the bitfield struct is avoided on purpose).
	case IPPROTO_TCP: {
		struct tcphdr *t = l4;

		if ((void *)(t + 1) > end)
			return PARSE_BAD;
		p->sport = bpf_ntohs(t->source);
		p->dport = bpf_ntohs(t->dest);
		p->tcp_flags = ((__u8 *)t)[13];
		break;
	}
	// UDP: only the ports are needed.
	case IPPROTO_UDP: {
		struct udphdr *u = l4;

		if ((void *)(u + 1) > end)
			return PARSE_BAD;
		p->sport = bpf_ntohs(u->source);
		p->dport = bpf_ntohs(u->dest);
		break;
	}
	// ICMP / ICMPv6: only the type byte is needed (to recognise neighbour discovery).
	case IPPROTO_ICMP:
	case IPPROTO_ICMPV6: {
		__u8 *i = l4;

		if (i + 1 > (__u8 *)end)
			return PARSE_BAD;
		p->icmp_type = i[0];
		break;
	}
	}
	return PARSE_OK;
}

// Parse Ethernet -> (VLAN)* -> IPv4/IPv6 -> L4 into p.
// Returns PARSE_OK, PARSE_NONIP (ARP, LLDP, ...), or PARSE_BAD (truncated).
static __always_inline int parse(struct xdp_md *ctx, struct pkt *p)
{
	void *data = (void *)(long)ctx->data;
	void *end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = data;
	void *cur;
	__u16 proto;

	// Bounds check: the Ethernet header must lie entirely within the packet.
	if ((void *)(eth + 1) > end)
		return PARSE_BAD;
	proto = eth->h_proto;
	cur = eth + 1;

// Skip up to two VLAN tags (802.1Q and QinQ 802.1ad). Unrolled so the verifier
// sees straight-line code; deeper stacks are rare and fall through as non-IP.
#pragma unroll
	for (int i = 0; i < 2; i++) {
		if (proto == bpf_htons(ETH_P_8021Q) ||
		    proto == bpf_htons(ETH_P_8021AD)) {
			struct vlan {
				__be16 tci;
				__be16 proto;
			} *v = cur;

			if ((void *)(v + 1) > end)
				return PARSE_BAD;
			proto = v->proto;
			cur = v + 1;
		}
	}

	// ---- IPv4 ----
	if (proto == bpf_htons(ETH_P_IP)) {
		struct iphdr *ip = cur;
		__u32 ihl;
		__u16 fo;

		if ((void *)(ip + 1) > end)
			return PARSE_BAD;
		// IHL is in 32-bit words; reject impossible values and headers that extend past
		// the end of the packet. l3len < ihl is also inconsistent.
		ihl = ip->ihl * 4;
		if (ihl < sizeof(*ip) || (void *)ip + ihl > end)
			return PARSE_BAD;
		p->l3len = bpf_ntohs(ip->tot_len);
		if (p->l3len < ihl)
			return PARSE_BAD;
		p->family = 4;
		p->proto = ip->protocol;
		p->ttl = ip->ttl;
		p->saddr[0] = ip->saddr;
		p->daddr[0] = ip->daddr;
		// Fragment classification. Later fragments carry no L4 header, so we must not
		// try to parse one (it would read payload bytes as if they were a header).
		fo = bpf_ntohs(ip->frag_off);
		if (fo & IP_OFFMASK)
			p->frag = 2;
		else if (fo & IP_MF_OFF)
			p->frag = 1;
		// Later fragment: no transport header to parse; stop here with L3 info only.
		if (p->frag == 2)
			return PARSE_OK;
		return parse_l4(p, (void *)ip + ihl, end);
	}

	// ---- IPv6 ----
	if (proto == bpf_htons(ETH_P_IPV6)) {
		struct ipv6hdr *ip6 = cur;
		void *l4;

		if ((void *)(ip6 + 1) > end)
			return PARSE_BAD;
		p->family = 6;
		p->proto = ip6->nexthdr;
		p->ttl = ip6->hop_limit;
		p->l3len = bpf_ntohs(ip6->payload_len) + sizeof(*ip6);
		__builtin_memcpy(p->saddr, &ip6->saddr, 16);
		__builtin_memcpy(p->daddr, &ip6->daddr, 16);
		l4 = ip6 + 1;
		// Only the Fragment extension header is understood. Other extension headers are
		// left in p->proto as an opaque next-header (documented limitation).
		if (p->proto == IPPROTO_FRAGMENT) {
			struct fh {
				__u8 nexthdr, rsvd;
				__be16 off;
				__be32 id;
			} *f = l4;

			if ((void *)(f + 1) > end)
				return PARSE_BAD;
			p->proto = f->nexthdr;
			if (bpf_ntohs(f->off) & 0xFFF8) {
				p->frag = 2;
				return PARSE_OK;
			}
			p->frag = 1;
			l4 = f + 1;
		}
		return parse_l4(p, l4, end);
	}
	// Neither IPv4 nor IPv6: ARP, LLDP, etc. The caller passes these untouched.
	return PARSE_NONIP;
}

/* ---------------------------------------------------------------- helpers */

// Account one packet to a stats slot. PERCPU array: the pointer we get is this
// CPU's own copy, so plain increments are race-free.
static __always_inline void stat_inc(__u32 idx, __u64 bytes)
{
	struct bladerunner_counter *c;

	// Mask so the verifier can bound the index (real maximum is BLADERUNNER_NSTAT - 1).
	idx &= 0xFF; /* verifier bound; real max is BLADERUNNER_NSTAT-1 */
	c = bpf_map_lookup_elem(&stats, &idx);
	if (c) {
		c->pkts++;
		c->bytes += bytes;
	}
}

// A prefix entry is live if it has no expiry or the expiry is still in the future.
static __always_inline int live(const struct bladerunner_lpm_val *v, __u64 now)
{
	return v && (!v->expires_ns || now < v->expires_ns);
}

// Is the packet's IPv4 SOURCE inside an LPM set (allow/block)? Full /32 key.
static __always_inline int in_set4(void *map, const struct pkt *p, __u64 now)
{
	struct bladerunner_lpm4_key k = { .prefixlen = 32, .addr = p->saddr[0] };

	return live(bpf_map_lookup_elem(map, &k), now);
}

// Same, for the DESTINATION address (used for the protected set).
static __always_inline int dst_in_set4(void *map, const struct pkt *p, __u64 now)
{
	struct bladerunner_lpm4_key k = { .prefixlen = 32, .addr = p->daddr[0] };

	return live(bpf_map_lookup_elem(map, &k), now);
}

// IPv6 equivalent; takes the 4-word address and builds a full /128 key.
static __always_inline int in_set6(void *map, const __u32 *a, __u64 now)
{
	struct bladerunner_lpm6_key k = { .prefixlen = 128 };

	__builtin_memcpy(k.addr, a, 16);
	return live(bpf_map_lookup_elem(map, &k), now);
}

// Family dispatch for source-address set membership.
static __always_inline int src_in(void *m4, void *m6, const struct pkt *p, __u64 now)
{
	return p->family == 4 ? in_set4(m4, p, now) : in_set6(m6, p->saddr, now);
}

// Family dispatch for destination-address set membership.
static __always_inline int dst_in(void *m4, void *m6, const struct pkt *p, __u64 now)
{
	return p->family == 4 ? dst_in_set4(m4, p, now) : in_set6(m6, p->daddr, now);
}

// (See below.) take_token implements a classic token bucket in integer math:
//  refill = elapsed_ns * pps / 1e9 tokens, capped at `burst`; one token per
//  packet. Returns 1 if the packet may pass, 0 if the bucket is empty.
/* Token bucket step. Racy across CPUs by design: approximate, never blocks. */
static __always_inline int take_token(struct bladerunner_bucket *b, __u32 pps, __u32 burst, __u64 now)
{
	__u64 el;

	// Clamp pps so elapsed(<10s) * pps cannot overflow 64 bits:
	// 10e9 ns * 1e9 pps = 1e19 < 1.8e19 (u64 max).
	if (pps > 1000000000U)
		pps = 1000000000U;
	if (!burst)
		burst = 1;
	// First use of a bucket: start full.
	if (!b->last_ns) {
		b->tokens = burst;
		b->last_ns = now;
	} else {
		el = now - b->last_ns;
		// Idle for >= 10 s: just refill completely (also sidesteps overflow).
		if (el >= 10000000000ULL) {
			b->tokens = burst;
			b->last_ns = now;
		} else {
			// Whole tokens earned since last_ns. last_ns only advances when add > 0, so at
			// low rates the fractional remainder accumulates instead of being discarded.
			__u64 add = el * pps / 1000000000ULL;

			if (add) {
				__u64 t = (__u64)b->tokens + add;

				b->tokens = t > burst ? burst : (__u32)t;
				b->last_ns = now;
			}
		}
	}
	// Spend one token. Not atomic across CPUs: the limiter is approximate by design.
	if (b->tokens) {
		b->tokens--;
		return 1;
	}
	return 0;
}

// Does a fingerprint rule match this packet? All conditions are ANDed. Wildcards
// are expressed as the widest range (0..65535 / 0..255), so no special-casing.
// For later fragments sport/dport are 0, which only the wildcard range matches.
/*
 * VERIFIER NOTE: this is deliberately a GLOBAL, NON-INLINED function (not
 * `static __always_inline` like the rest). The kernel verifies a global
 * function ONCE, in isolation, and the caller then sees only an unknown
 * scalar result. If it were inlined, every early `return 0` below would fork
 * the verifier's state in each of the 32 loop iterations in bladerunner_xdp(), and the
 * path count multiplies. That blew through the kernel's 1,000,000-instruction
 * budget on some kernels (see TestVerifierComplexity).
 */
__attribute__((noinline)) int fp_match(const struct bladerunner_fp_rule *r, const struct pkt *p, __u64 now)
{
	/* Pointer args of a global function must be treated as possibly NULL by
	 * the verifier (newer kernels enforce this), so check before use. */
	if (!r || !p)
		return 0;
	if (r->action == BLADERUNNER_FP_NONE)
		return 0;
	if (r->expires_ns && now >= r->expires_ns)
		return 0;
	if (r->family && r->family != p->family)
		return 0;
	if (r->proto && r->proto != p->proto)
		return 0;
	if (p->sport < r->sport_lo || p->sport > r->sport_hi)
		return 0;
	if (p->dport < r->dport_lo || p->dport > r->dport_hi)
		return 0;
	if (p->l3len < r->len_lo || p->l3len > r->len_hi)
		return 0;
	if (p->ttl < r->ttl_lo || p->ttl > r->ttl_hi)
		return 0;
	if (r->tcp_flags_mask && (p->tcp_flags & r->tcp_flags_mask) != r->tcp_flags_val)
		return 0;
	return 1;
}

// Choose the rate-limit class: SYNs (no ACK) and DNS get their own tighter
// budgets, because those are the classic flood vectors.
static __always_inline int rate_class(const struct pkt *p)
{
	switch (p->proto) {
	case IPPROTO_TCP:
		if ((p->tcp_flags & (TCP_SYN | TCP_ACK)) == TCP_SYN)
			return BLADERUNNER_C_SYN;
		return BLADERUNNER_C_ANY;
	case IPPROTO_UDP:
		return p->dport == 53 ? BLADERUNNER_C_DNS : BLADERUNNER_C_UDP;
	case IPPROTO_ICMP:
	case IPPROTO_ICMPV6:
		return BLADERUNNER_C_ICMP;
	}
	return BLADERUNNER_C_ANY;
}

/* Returns 1 when the packet is within its source's budget. */
// Per-source rate limit. Returns 1 if the packet is within budget.
// The budget set depends on the attack flag (c->attack), so entering attack
// mode tightens every source's limit without touching any per-source state.
static __always_inline int source_ok(const struct bladerunner_config *c, const struct pkt *p, __u64 now)
{
	__u32 cls = rate_class(p) & (BLADERUNNER_NCLASS - 1);
	__u32 att = c->attack & 1;
	__u32 pps = c->lim[att][cls].pps;
	__u32 burst = c->lim[att][cls].burst;
	struct bladerunner_bucket *b;

	// pps == 0 means this class is unlimited: skip the bucket entirely.
	if (!pps)
		return 1;

	// IPv4: key on the full source address.
	if (p->family == 4) {
		struct bladerunner_rl4_key k = { .addr = p->saddr[0], .class = cls };

		b = bpf_map_lookup_elem(&rl4, &k);
		if (!b) {
			// Unknown source: create its bucket with this packet already charged. BPF_ANY on
			// an LRU map evicts the oldest entry if full, so insertion cannot fail.
			struct bladerunner_bucket nb = { .last_ns = now, .tokens = burst ? burst - 1 : 0 };

			bpf_map_update_elem(&rl4, &k, &nb, BPF_ANY);
			return 1;
		}
	} else {
		struct bladerunner_rl6_key k = { .addr_hi = ((__u64)p->saddr[1] << 32) | p->saddr[0],
					.class = cls };

		b = bpf_map_lookup_elem(&rl6, &k);
		if (!b) {
			struct bladerunner_bucket nb = { .last_ns = now, .tokens = burst ? burst - 1 : 0 };

			bpf_map_update_elem(&rl6, &k, &nb, BPF_ANY);
			return 1;
		}
	}
	// Known source: charge a token. (IPv6 branch above keys on the /64 prefix.)
	return take_token(b, pps, burst, now);
}

// Probabilistically copy header-derived metadata to the ring buffer. Called for
// every verdict, so dropped traffic is sampled too. If the ring buffer is full
// the sample is lost and counted; the data plane never blocks on it.
static __always_inline void emit_sample(const struct bladerunner_config *c, const struct pkt *p,
					__u32 reason, __u64 now, __u32 wire)
{
	struct bladerunner_sample *s;

	if (!c->sample_rate || bpf_get_prandom_u32() % c->sample_rate)
		return;
	// Reserve space; NULL means the buffer is full.
	s = bpf_ringbuf_reserve(&samples, sizeof(*s), 0);
	if (!s) {
		stat_inc(BLADERUNNER_S_SAMPLE_LOST, 0);
		return;
	}
	s->ts_ns = now;
	__builtin_memcpy(s->saddr, p->saddr, 16);
	__builtin_memcpy(s->daddr, p->daddr, 16);
	s->sport = p->sport;
	s->dport = p->dport;
	s->l3_len = p->l3len;
	s->wire_len = wire > 0xFFFF ? 0xFFFF : wire;
	s->family = p->family;
	s->proto = p->proto;
	s->ttl = p->ttl;
	s->tcp_flags = p->tcp_flags;
	s->reason = reason;
	s->icmp_type = p->icmp_type;
	s->frag = p->frag;
	s->_pad = 0;
	bpf_ringbuf_submit(s, 0);
	stat_inc(BLADERUNNER_S_SAMPLED, 0);
}

// Single exit point: account the packet, maybe sample it, then convert the
// reason to an XDP action. Dry-run suppresses only the DROP, never the
// accounting, so dry-run counters equal what enforcement would have done.
static __always_inline int finish(const struct bladerunner_config *c, const struct pkt *p,
				  __u32 reason, __u64 now, __u32 wire)
{
	stat_inc(reason, wire);
	emit_sample(c, p, reason, now, wire);
	if (reason >= BLADERUNNER_R_BLOCKLIST && !(c->flags & BLADERUNNER_F_DRYRUN))
		return XDP_DROP;
	return XDP_PASS;
}

/* ------------------------------------------------------------------ main */

// Program entry point, run for every received frame on the attached interface.
// Stages run in a fixed order and the first that decides ends processing; see
// docs/ARCHITECTURE.md for the rationale behind the order.
SEC("xdp")
int bladerunner_xdp(struct xdp_md *ctx)
{
	__u32 zero = 0;
	const struct bladerunner_config *c = bpf_map_lookup_elem(&cfg, &zero);
	struct pkt p = {};
	__u64 now = bpf_ktime_get_ns();
	__u32 wire = (__u32)((long)ctx->data_end - (long)ctx->data);
	int pr;

	// Fail open: with no config (should be impossible) pass everything.
	if (!c)
		return XDP_PASS; /* fail open */

	// Stage 1: parse. Non-IP is left alone; malformed packets are dropped.
	pr = parse(ctx, &p);
	if (pr == PARSE_NONIP)
		return finish(c, &p, BLADERUNNER_R_NONIP, now, wire);
	if (pr == PARSE_BAD)
		return finish(c, &p, BLADERUNNER_R_MALFORMED, now, wire);

	// Stage 2: allowlist. Checked before everything else so it always wins.
	if (src_in(&allow4, &allow6, &p, now))
		return finish(c, &p, BLADERUNNER_R_ALLOW, now, wire);

	// Stage 3: neighbour discovery exemption (RFC 4861). Hop limit 255 proves the
	// packet never crossed a router, so it is genuine link-local control traffic.
	// Dropping it would knock the host off the network.
	/* IPv6 neighbour discovery is link-local control traffic: pass it
	 * when the hop limit proves it did not cross a router (RFC 4861). */
	if (p.proto == IPPROTO_ICMPV6 && p.ttl == 255 &&
	    p.icmp_type >= 133 && p.icmp_type <= 137)
		return finish(c, &p, BLADERUNNER_R_EXEMPT, now, wire);

	// Stage 4: scope. If protected-only is on, anything not aimed at the protected set is ignored.
	if ((c->flags & BLADERUNNER_F_PROTECTED_ONLY) && !dst_in(&protect4, &protect6, &p, now))
		return finish(c, &p, BLADERUNNER_R_UNPROT, now, wire);

	// Stage 5: static / auto blocklist (entries may carry an in-kernel TTL).
	if (src_in(&block4, &block6, &p, now))
		return finish(c, &p, BLADERUNNER_R_BLOCKLIST, now, wire);

	// Stage 6: protocol sanity. NULL scans, SYN+FIN, SYN+RST and port 0 have no
	// legitimate use and are common in crafted floods.
	if (c->flags & BLADERUNNER_F_SANITY) {
		if (p.proto == IPPROTO_TCP && p.frag != 2) {
			__u8 f = p.tcp_flags;

			if (f == 0 || (f & (TCP_SYN | TCP_FIN)) == (TCP_SYN | TCP_FIN) ||
			    (f & (TCP_SYN | TCP_RST)) == (TCP_SYN | TCP_RST) ||
			    p.sport == 0 || p.dport == 0)
				return finish(c, &p, BLADERUNNER_R_INVALID, now, wire);
		}
		if (p.proto == IPPROTO_UDP && p.frag != 2 && p.dport == 0)
			return finish(c, &p, BLADERUNNER_R_INVALID, now, wire);
	}

	// Stage 7: fragments. Rare in legitimate edge traffic and a common evasion/reflection vector.
	if ((c->flags & BLADERUNNER_F_DROP_FRAGS) && p.frag)
		return finish(c, &p, BLADERUNNER_R_FRAG, now, wire);

	// Stage 8: UDP reflection. Replies sourced from well-known reflector ports (NTP,
	// memcached, CLDAP, ...) are dropped above a minimum size.
	if ((c->flags & BLADERUNNER_F_AMP) && p.proto == IPPROTO_UDP && p.frag != 2) {
		__u16 sp = p.sport;
		struct bladerunner_amp *a = bpf_map_lookup_elem(&amp_ports, &sp);

		if (a && (a->min_len == 0 || p.l3len >= a->min_len))
			return finish(c, &p, BLADERUNNER_R_AMP, now, wire);
	}

	/* Fingerprint rules, installed by the control plane from sampled data. */
	// Stage 9: fingerprint rules. The loop bound is a compile-time constant, which
	// is what lets the verifier accept it; the early `break` makes cost proportional
	// to the number of installed rules.
	for (__u32 i = 0; i < BLADERUNNER_MAX_FP_RULES; i++) {
		struct bladerunner_fp_rule *r;
		struct bladerunner_fp_counter *fc;
		__u32 k = i;

		if (i >= c->fp_n)
			break;
		r = bpf_map_lookup_elem(&fp_rules, &k);
		if (!r)
			break;
		if (!fp_match(r, &p, now))
			continue;
		fc = bpf_map_lookup_elem(&fp_counters, &k);
		if (fc) {
			fc->matched_pkts++;
			fc->matched_bytes += wire;
		}
		// Rate-limit rules share one bucket across all matching packets. If a token is
		// available (or the bucket is missing) the packet is spared by this rule and
		// evaluation continues with the next rule.
		if (r->action == BLADERUNNER_FP_RATELIMIT) {
			struct bladerunner_bucket *b = bpf_map_lookup_elem(&fp_buckets, &k);

			if (!b || take_token(b, r->rate_pps, r->burst, now))
				continue;
		}
		if (fc) {
			fc->dropped_pkts++;
			fc->dropped_bytes += wire;
		}
		return finish(c, &p, BLADERUNNER_R_FPRULE, now, wire);
	}

	// Stage 10: per-source rate limit (limit set depends on attack state).
	if ((c->flags & BLADERUNNER_F_RATELIMIT) && !source_ok(c, &p, now))
		return finish(c, &p, BLADERUNNER_R_RATE, now, wire);

	// Nothing objected: pass.
	return finish(c, &p, BLADERUNNER_R_PASS, now, wire);
}
