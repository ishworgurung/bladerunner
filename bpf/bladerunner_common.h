/* SPDX-License-Identifier: MIT */
/*
 * bladerunner_common.h - structures and constants shared between the XDP program
 * (bladerunner.bpf.c) and the Go control plane.
 *
 * CONTRACT: internal/bpf/types.go mirrors every struct in this file byte for
 * byte. If you change a struct here you MUST change the Go mirror too; the
 * TestLayout test in internal/bpf compares the Go sizes against the key/value
 * sizes the kernel reports for each loaded map, so a mismatch fails CI.
 *
 * Layout rules followed throughout:
 *   - fixed-width types only (__u8/__u16/__u32/__u64), never int/long;
 *   - every struct is naturally aligned, with explicit _pad fields wherever
 *     the compiler would otherwise insert invisible padding (so Go and C agree);
 *   - 64-bit fields come first where possible to avoid tail padding.
 */
#ifndef BLADERUNNER_COMMON_H
#define BLADERUNNER_COMMON_H

#include <linux/types.h>

/*
 * Maximum number of fingerprint rules. The data plane scans them linearly
 * with a loop bounded by this constant, which keeps the verifier's path
 * exploration small. Raising it increases verifier cost roughly linearly;
 * re-run the kernel tests (make test) after changing it.
 */
#define BLADERUNNER_MAX_FP_RULES 32

/*
 * Number of rate-limit classes in bladerunner_config.lim[][]. Must be a power of two:
 * the program indexes with (class & (BLADERUNNER_NCLASS - 1)) so the verifier can prove
 * the index is in range without a branch.
 */
#define BLADERUNNER_NCLASS 8

/*
 * Verdict reasons. Every packet that reaches the program is accounted to
 * EXACTLY ONE reason (one counter increment per packet, so summing all reasons
 * gives total offered load; the control plane's attack detector relies on that).
 *
 * ORDER MATTERS: reasons >= BLADERUNNER_R_BLOCKLIST are dropping verdicts (or "would
 * drop" in dry-run mode). finish() in the BPF program and IsDrop() in Go both
 * use that boundary, and the Go constants in types.go must keep this order.
 */
enum bladerunner_reason {
	BLADERUNNER_R_PASS = 0,	  /* passed every filter: normal traffic */
	BLADERUNNER_R_ALLOW,	  /* source is allowlisted: never filtered */
	BLADERUNNER_R_EXEMPT,	  /* essential control traffic (IPv6 neighbour discovery) */
	BLADERUNNER_R_NONIP,	  /* not IPv4/IPv6 (ARP, LLDP, ...): never touched */
	BLADERUNNER_R_UNPROT,	  /* destination outside the protected set: never touched */
	BLADERUNNER_R_BLOCKLIST,	  /* source is blocklisted (first dropping reason) */
	BLADERUNNER_R_AMP,	  /* UDP reflection/amplification source port */
	BLADERUNNER_R_FRAG,	  /* IP fragment */
	BLADERUNNER_R_FPRULE,	  /* matched an attack fingerprint rule */
	BLADERUNNER_R_RATE,	  /* per-source rate limit exceeded */
	BLADERUNNER_R_INVALID,	  /* invalid TCP flag combination / port 0 */
	BLADERUNNER_R_MALFORMED,	  /* truncated or inconsistent IP headers */
	BLADERUNNER_NREASON,	  /* number of reasons (not a reason itself) */
};

/*
 * Extra counters that live in the same stats array, after the reasons. They
 * are not verdicts: they count ring-buffer sampling outcomes.
 */
enum bladerunner_stat_extra {
	BLADERUNNER_S_SAMPLED = BLADERUNNER_NREASON, /* samples delivered to the ring buffer */
	BLADERUNNER_S_SAMPLE_LOST,	   /* samples lost because the ring buffer was full */
	BLADERUNNER_NSTAT,		   /* total number of stats slots */
};

/*
 * Per-source rate-limit classes. Each class has its own token bucket per
 * source address, so a UDP flood from a host does not starve its own SYNs.
 */
enum bladerunner_class {
	BLADERUNNER_C_ANY = 0, /* everything not matched below (e.g. established TCP) */
	BLADERUNNER_C_SYN,     /* TCP SYN without ACK (connection attempts) */
	BLADERUNNER_C_UDP,     /* UDP except DNS */
	BLADERUNNER_C_DNS,     /* UDP to destination port 53 */
	BLADERUNNER_C_ICMP,    /* ICMP and ICMPv6 */
};

/* ---- bladerunner_config.flags bits -------------------------------------------- */
#define BLADERUNNER_F_DRYRUN (1U << 0)	      /* account everything, but never return XDP_DROP */
#define BLADERUNNER_F_DROP_FRAGS (1U << 1)     /* drop IP fragments */
#define BLADERUNNER_F_AMP (1U << 2)	      /* apply the amplification source-port table */
#define BLADERUNNER_F_PROTECTED_ONLY (1U << 3) /* only filter traffic destined to the protected set */
#define BLADERUNNER_F_RATELIMIT (1U << 4)      /* enable per-source token buckets */
#define BLADERUNNER_F_SANITY (1U << 5)	      /* drop invalid TCP flags / port 0 */

/* ---- bladerunner_fp_rule.action values ---------------------------------------- */
#define BLADERUNNER_FP_NONE 0	  /* empty slot: never matches */
#define BLADERUNNER_FP_DROP 1	  /* drop every matching packet */
#define BLADERUNNER_FP_RATELIMIT 2 /* one token bucket SHARED by all matching packets */

/*
 * A token-bucket budget: sustained rate and burst depth, both in packets.
 * pps == 0 means "unlimited" (the bucket is skipped entirely).
 */
struct bladerunner_limit {
	__u32 pps;   /* sustained packets/sec per source; 0 = unlimited */
	__u32 burst; /* bucket depth in packets (max burst after idle) */
};

/*
 * Runtime configuration: a single entry in the `cfg` ARRAY map. The control
 * plane rewrites it as a whole; the data plane reads it once per packet.
 * Because it is a plain struct in a map value, an update takes effect for the
 * next packet on each CPU without reloading the program.
 */
struct bladerunner_config {
	__u32 flags;       /* BLADERUNNER_F_* bits */
	__u32 sample_rate; /* send 1-in-N packets to the ring buffer; 0 = off */
	__u32 fp_n;	   /* number of fingerprint slots to scan (0..BLADERUNNER_MAX_FP_RULES) */
	__u32 attack;	   /* 0 = use lim[0] (normal), 1 = use lim[1] (attack) */
	struct bladerunner_limit lim[2][BLADERUNNER_NCLASS]; /* indexed [attack][class] */
};

/*
 * LPM trie keys. The kernel REQUIRES prefixlen to be the first u32 of the key,
 * followed by the address bytes in network order (as they appear on the wire).
 * Lookups use the full-length key (/32 or /128); the trie returns the longest
 * stored prefix that covers it.
 */
struct bladerunner_lpm4_key {
	__u32 prefixlen;
	__u32 addr; /* IPv4 address, network byte order */
};

struct bladerunner_lpm6_key {
	__u32 prefixlen;
	__u8 addr[16]; /* IPv6 address, network byte order */
};

/*
 * Value stored for every allow/block/protect prefix. expires_ns is checked by
 * the data plane on every lookup, so a TTL entry stops matching the instant it
 * expires even if the daemon is dead and never deletes it.
 */
struct bladerunner_lpm_val {
	__u64 expires_ns; /* CLOCK_MONOTONIC ns (bpf_ktime_get_ns); 0 = never expires */
	__u32 flags;	  /* reserved for future use */
	__u32 _pad;	  /* explicit tail padding (keeps sizeof == 16 in C and Go) */
};

/*
 * Amplification-port table value. Key is the UDP SOURCE port (e.g. 123 for NTP
 * replies, 11211 for memcached). A packet is dropped when its L3 length is at
 * least min_len; this lets small legitimate replies through while dropping the
 * large amplified ones.
 */
struct bladerunner_amp {
	__u16 min_len; /* 0 = drop every packet from this source port */
	__u16 _pad;
};

/*
 * One fingerprint rule: a conjunction of range/exact matches over packet
 * fields. Installed by the control plane from sampled traffic. A rule with all
 * ranges at their widest and proto/family 0 would match everything, so the
 * control plane always constrains at least proto, one port, length and TTL.
 */
struct bladerunner_fp_rule {
	__u64 expires_ns; /* CLOCK_MONOTONIC ns after which the rule stops matching; 0 = never */
	__u32 rate_pps;	  /* BLADERUNNER_FP_RATELIMIT: shared rate for ALL matching packets */
	__u32 burst;	  /* BLADERUNNER_FP_RATELIMIT: shared bucket depth */
	__u16 sport_lo, sport_hi; /* inclusive source-port range; 0..65535 = wildcard */
	__u16 dport_lo, dport_hi; /* inclusive destination-port range */
	__u16 len_lo, len_hi;	  /* inclusive L3 total-length range (bytes) */
	__u8 proto;		  /* IP protocol number; 0 = any */
	__u8 action;		  /* BLADERUNNER_FP_* */
	__u8 family;		  /* 0 = any, 4 = IPv4, 6 = IPv6 */
	__u8 tcp_flags_mask;	  /* match when (flags & mask) == val; mask 0 = ignore flags */
	__u8 tcp_flags_val;
	__u8 ttl_lo, ttl_hi;	  /* inclusive TTL / hop-limit range */
	__u8 _pad;
	__u32 id;		  /* control-plane bookkeeping; unused by the data plane */
};

/* Per-rule counters (PERCPU_ARRAY: one copy per CPU, summed in userspace). */
struct bladerunner_fp_counter {
	__u64 matched_pkts;
	__u64 matched_bytes;
	__u64 dropped_pkts; /* matched and not saved by a rate-limit bucket */
	__u64 dropped_bytes;
};

/* Generic packet/byte counter, used for the per-reason stats. */
struct bladerunner_counter {
	__u64 pkts;
	__u64 bytes;
};

/*
 * Token bucket state. tokens counts packets. last_ns is the time the bucket
 * was last refilled; it is only advanced when at least one whole token was
 * added, so fractional refill is never lost at low rates.
 */
struct bladerunner_bucket {
	__u64 last_ns;
	__u32 tokens;
	__u32 _pad;
};

/* Rate-limit map keys: one bucket per (source, class). */
struct bladerunner_rl4_key {
	__u32 addr;  /* IPv4 source, network byte order */
	__u32 class; /* enum bladerunner_class */
};

struct bladerunner_rl6_key {
	__u64 addr_hi; /* first 64 bits of the source: IPv6 is limited per /64 */
	__u32 class;
	__u32 _pad;
};

/*
 * Record pushed to the sampling ring buffer for 1-in-sample_rate packets.
 * It is sampled for EVERY verdict (including drops) and carries the verdict
 * reason, so the control plane keeps seeing an attack it is already blocking.
 * Packet payload is never copied: only header-derived fields.
 */
struct bladerunner_sample {
	__u64 ts_ns;	    /* CLOCK_MONOTONIC at sampling time */
	__u32 saddr[4];	    /* IPv4: saddr[0] only; both in raw network-order bytes */
	__u32 daddr[4];
	__u16 sport, dport; /* host byte order; 0 if no L4 header was parsed */
	__u16 l3_len, wire_len; /* IP total length / bytes on the wire (clamped to 65535) */
	__u8 family, proto, ttl, tcp_flags;
	__u8 reason;	    /* enum bladerunner_reason that decided this packet */
	__u8 icmp_type;
	__u8 frag;	    /* 0 none, 1 first fragment, 2 later fragment */
	__u8 _pad;
};

#endif /* BLADERUNNER_COMMON_H */
