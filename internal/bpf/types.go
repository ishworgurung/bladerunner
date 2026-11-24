// Package bpf loads the bladerunner XDP object and exposes typed access to
// its maps. The structs below mirror bpf/bladerunner_common.h exactly; TestLayout
// verifies every size against the loaded object.
package bpf

// The constants below mirror enum bladerunner_reason / bladerunner_stat_extra / bladerunner_class and the
// BLADERUNNER_F_* / BLADERUNNER_FP_* defines in bpf/bladerunner_common.h. ORDER IS A CONTRACT with the C
// side: the numeric values are used directly as stats-array indices.
// Reasons (BLADERUNNER_R_*). Order matches the C enum.
const (
	// RPass is traffic that passed every filter.
	RPass = iota
	// RAllow: the source matched the allowlist.
	RAllow
	// RExempt: essential link-local control traffic (IPv6 neighbour discovery).
	RExempt
	// RNonIP: not IPv4/IPv6, left untouched.
	RNonIP
	// RUnprot: destination outside the protected set, left untouched.
	RUnprot
	// RBlocklist is the first DROPPING reason; everything from here on drops.
	RBlocklist
	// RAmp: UDP reflection source port.
	RAmp
	// RFrag: IP fragment.
	RFrag
	// RFPRule: matched a control-plane fingerprint rule.
	RFPRule
	// RRate: per-source rate limit exceeded.
	RRate
	// RInvalid: invalid TCP flags or port 0.
	RInvalid
	// RMalformed: truncated or inconsistent headers.
	RMalformed
	// NReason is the number of reasons (not a reason).
	NReason
)

// Extra stats slots (BLADERUNNER_S_*) after the reasons. They count ring-buffer outcomes,
// not verdicts, so IsDrop must never be applied to them.
const (
	SSampled    = NReason
	SSampleLost = NReason + 1
	NStat       = NReason + 2
)

// ReasonNames gives the stable, human/metric-friendly label of each reason. These
// strings appear in `bladerunner stats` output and as the `reason` label in Prometheus.
var ReasonNames = [NReason]string{
	"pass", "allow", "exempt", "non_ip", "unprotected", "blocklist",
	"amp_port", "fragment", "fp_rule", "rate_limit", "invalid", "malformed",
}

// IsDrop reports whether a reason is a dropping verdict (when not in dry-run).
// It relies on RBlocklist being the first dropping reason.
func IsDrop(r int) bool { return r >= RBlocklist }

// Rate-limit classes (BLADERUNNER_C_*). Each class has its own per-source token bucket.
// NClass is the array width in bladerunner_config and must stay a power of two.
const (
	CAny = iota
	CSyn
	CUDP
	CDNS
	CICMP
	NClass = 8
)

// Config flags (BLADERUNNER_F_*): bit positions inside Config.Flags.
const (
	// FDryRun: classify and count, but never drop.
	FDryRun = 1 << 0
	// FDropFrags: drop IP fragments.
	FDropFrags = 1 << 1
	// FAmp: enable the amplification source-port table.
	FAmp = 1 << 2
	// FProtectedOnly: restrict filtering to traffic destined to the protected set.
	FProtectedOnly = 1 << 3
	// FRateLimit: enable per-source token buckets.
	FRateLimit = 1 << 4
	// FSanity: drop invalid TCP flag combinations and port 0.
	FSanity = 1 << 5
)

// Fingerprint rule actions (BLADERUNNER_FP_*).
const (
	FPNone      = 0
	FPDrop      = 1
	FPRateLimit = 2
)

// MaxFPRules is BLADERUNNER_MAX_FP_RULES, the fingerprint table size (verifier-bounded loop).
const MaxFPRules = 32

// Limit is a token-bucket budget. PPS is the sustained rate in packets/second
// (0 = unlimited); Burst is the bucket depth in packets.
type Limit struct{ PPS, Burst uint32 }

// Config mirrors struct bladerunner_config (144 bytes): 4 x u32 header plus
// Lim[attack][class]. Lim[0] applies normally, Lim[1] while under attack.
// FPN is how many fingerprint slots the data plane scans; Attack is 0 or 1.
type Config struct {
	Flags      uint32
	SampleRate uint32
	FPN        uint32
	Attack     uint32
	Lim        [2][NClass]Limit
}

// LPMVal mirrors struct bladerunner_lpm_val (16 bytes). ExpiresNS is a CLOCK_MONOTONIC
// timestamp enforced by the data plane itself; 0 means permanent.
type LPMVal struct {
	ExpiresNS uint64
	Flags     uint32
	_         uint32
}

// Amp mirrors struct bladerunner_amp (4 bytes): MinLen is the L3 length at/above which a reflector-port packet is dropped.
// Amp mirrors struct bladerunner_amp (4 bytes).
type Amp struct {
	MinLen uint16
	_      uint16
}

// FPRule mirrors struct bladerunner_fp_rule (40 bytes). All fields are ANDed; ranges are
// inclusive, with 0..65535 (ports/length) and 0..255 (TTL) acting as wildcards.
// Padding fields are explicit so the Go layout equals the C layout.
type FPRule struct {
	ExpiresNS        uint64
	RatePPS          uint32
	Burst            uint32
	SportLo, SportHi uint16
	DportLo, DportHi uint16
	LenLo, LenHi     uint16
	Proto            uint8
	Action           uint8
	Family           uint8
	TCPFlagsMask     uint8
	TCPFlagsVal      uint8
	TTLLo, TTLHi     uint8
	_                uint8
	ID               uint32
}

// FPCounter mirrors struct bladerunner_fp_counter (32 bytes); read per-CPU and summed by ReadFPCounters.
type FPCounter struct{ MatchedPkts, MatchedBytes, DroppedPkts, DroppedBytes uint64 }

// Counter mirrors struct bladerunner_counter (16 bytes): a packet/byte pair.
type Counter struct{ Pkts, Bytes uint64 }

// Bucket mirrors struct bladerunner_bucket (16 bytes). Only used for size checking in tests; userspace never edits buckets.
type Bucket struct {
	LastNS uint64
	Tokens uint32
	_      uint32
}

// lpm4Key / lpm6Key are the LPM trie keys. PrefixLen MUST be first (kernel
// requirement); the address is in network byte order, which is the natural byte
// order of netip.Addr.As4()/As16().
type lpm4Key struct {
	PrefixLen uint32
	Addr      [4]byte
}

type lpm6Key struct {
	PrefixLen uint32
	Addr      [16]byte
}

// Sample mirrors struct bladerunner_sample (56 bytes), the ring-buffer record. Saddr/Daddr
// hold raw network-order bytes packed into native-endian u32 words (the BPF
// program memcpy'd them); detect.SourcePrefix reverses that. Sport/Dport/lengths
// are host order.
type Sample struct {
	TsNS                      uint64
	Saddr, Daddr              [4]uint32
	Sport, Dport              uint16
	L3Len, WireLen            uint16
	Family, Proto, TTL, Flags uint8
	Reason, ICMPType, Frag    uint8
	_                         uint8
}
