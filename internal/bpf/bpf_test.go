package bpf

// These tests load the REAL program into the running kernel (so the verifier
// actually runs) and push synthetic Ethernet frames through it with
// BPF_PROG_TEST_RUN (Program.Test). No network interface is touched. They need
// root/CAP_BPF and skip themselves (not fail) when BPF cannot be loaded, so
// `go test ./...` is safe on unprivileged machines.
import (
	"encoding/binary"
	"errors"
	"net/netip"
	"os"
	"testing"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sys/unix"
)

// XDP action codes as returned by the program (include/uapi/linux/bpf.h: XDP_DROP=1, XDP_PASS=2).
const (
	xdpDrop = 1
	xdpPass = 2
)

// load loads the program for one test and arranges cleanup. Every test gets a fresh set of maps.
func load(t *testing.T) *Objects {
	t.Helper()
	o, err := Load()
	if err != nil {
		// Skip ONLY when we lack privilege (and the environment does not demand
		// BPF). Any other failure - above all a verifier rejection - must fail
		// loudly: skipping it once hid a real "program too large" failure in CI.
		priv := errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) || errors.Is(err, os.ErrPermission)
		if priv && os.Getenv("BLADERUNNER_REQUIRE_BPF") == "" {
			t.Skipf("cannot load BPF (need CAP_BPF/root): %v", err)
		}
		t.Fatalf("cannot load BPF: %v", err)
	}
	t.Cleanup(o.Close)
	return o
}

// defaultCfg enables every filter with all rate limits OFF (pps 0), so a test only sees the filter it is about.
func defaultCfg() Config {
	c := Config{Flags: FDropFrags | FAmp | FRateLimit | FSanity}
	for a := 0; a < 2; a++ {
		for i := range c.Lim[a] {
			c.Lim[a][i] = Limit{PPS: 0, Burst: 0}
		}
	}
	return c
}

// run injects one frame and returns the XDP verdict.
func run(t *testing.T, o *Objects, pkt []byte) uint32 {
	t.Helper()
	ret, _, err := o.Prog.Test(pkt)
	if err != nil {
		t.Fatalf("test run: %v", err)
	}
	return ret
}

// Packet builders. Hand-rolled so the tests depend on nothing but encoding/binary
// and so every byte of each synthetic frame is visible in the test source.
// ---- packet builders

// eth builds a 14-byte Ethernet header with the given ethertype and dummy MACs.
func eth(proto uint16) []byte {
	b := make([]byte, 14)
	copy(b[0:6], []byte{2, 0, 0, 0, 0, 1})
	copy(b[6:12], []byte{2, 0, 0, 0, 0, 2})
	binary.BigEndian.PutUint16(b[12:], proto)
	return b
}

// ip4 wraps payload in an IPv4 header (no options, TTL 64). fragOff is the raw
// flags+offset field, e.g. 0x2000 = first fragment (MF), 0x00b9 = offset 185.
func ip4(src, dst string, proto byte, payload []byte, fragOff uint16) []byte {
	h := make([]byte, 20)
	h[0] = 0x45
	binary.BigEndian.PutUint16(h[2:], uint16(20+len(payload)))
	binary.BigEndian.PutUint16(h[6:], fragOff)
	h[8] = 64
	h[9] = proto
	s, d := netip.MustParseAddr(src).As4(), netip.MustParseAddr(dst).As4()
	copy(h[12:], s[:])
	copy(h[16:], d[:])
	return append(append(eth(0x0800), h...), payload...)
}

// udp builds a UDP header followed by n zero bytes of payload.
func udp(sp, dp uint16, n int) []byte {
	b := make([]byte, 8+n)
	binary.BigEndian.PutUint16(b[0:], sp)
	binary.BigEndian.PutUint16(b[2:], dp)
	binary.BigEndian.PutUint16(b[4:], uint16(8+n))
	return b
}

// tcp builds a minimal 20-byte TCP header with the given flags byte.
func tcp(sp, dp uint16, flags byte) []byte {
	b := make([]byte, 20)
	binary.BigEndian.PutUint16(b[0:], sp)
	binary.BigEndian.PutUint16(b[2:], dp)
	b[12] = 5 << 4
	b[13] = flags
	return b
}

// ip6 wraps payload in an IPv6 header; hl is the hop limit (255 matters for neighbour discovery).
func ip6(src, dst string, nh, hl byte, payload []byte) []byte {
	h := make([]byte, 40)
	h[0] = 0x60
	binary.BigEndian.PutUint16(h[4:], uint16(len(payload)))
	h[6] = nh
	h[7] = hl
	s, d := netip.MustParseAddr(src).As16(), netip.MustParseAddr(dst).As16()
	copy(h[8:], s[:])
	copy(h[24:], d[:])
	return append(append(eth(0x86dd), h...), payload...)
}

// Tests.
// ---- tests

// TestLayout guards the C<->Go struct contract: every map's key/value size as
// reported by the kernel must equal the size of the corresponding Go struct.
func TestLayout(t *testing.T) {
	o := load(t)
	chk := func(name string, m *ebpf.Map, k, v uintptr) {
		t.Helper()
		if uintptr(m.KeySize()) != k && k != 0 {
			t.Errorf("%s key size: kernel %d, go %d", name, m.KeySize(), k)
		}
		if uintptr(m.ValueSize()) != v && v != 0 {
			t.Errorf("%s value size: kernel %d, go %d", name, m.ValueSize(), v)
		}
	}
	chk("cfg", o.Cfg, 4, unsafe.Sizeof(Config{}))
	chk("stats", o.Stats, 4, unsafe.Sizeof(Counter{}))
	chk("allow4", o.Allow4, unsafe.Sizeof(lpm4Key{}), unsafe.Sizeof(LPMVal{}))
	chk("block6", o.Block6, unsafe.Sizeof(lpm6Key{}), unsafe.Sizeof(LPMVal{}))
	chk("amp", o.AmpPorts, 2, unsafe.Sizeof(Amp{}))
	chk("fp_rules", o.FPRules, 4, unsafe.Sizeof(FPRule{}))
	chk("fp_counters", o.FPCounters, 4, unsafe.Sizeof(FPCounter{}))
	chk("fp_buckets", o.FPBuckets, 4, unsafe.Sizeof(Bucket{}))
	chk("rl4", o.RL4, 8, unsafe.Sizeof(Bucket{}))
	chk("rl6", o.RL6, 16, unsafe.Sizeof(Bucket{}))
	if s := unsafe.Sizeof(Sample{}); s != 56 {
		t.Errorf("Sample size %d, want 56", s)
	}
}

// A zero-filled config (everything off) must pass traffic: the program fails open
// until the control plane configures it. Then a clean packet passes with all filters on.
func TestPassAndFailOpen(t *testing.T) {
	o := load(t)
	pkt := ip4("198.51.100.7", "203.0.113.1", 17, udp(4000, 5000, 100), 0)
	// Config entry is zero-initialised: everything off, must pass.
	if r := run(t, o, pkt); r != xdpPass {
		t.Fatalf("zero config: got %d", r)
	}
	if err := o.SetConfig(defaultCfg()); err != nil {
		t.Fatal(err)
	}
	if r := run(t, o, pkt); r != xdpPass {
		t.Fatalf("clean packet: got %d", r)
	}
}

// Covers: blocklist drops, allowlist overrides blocklist, and in-kernel TTL expiry
// (an expired entry stops matching without anyone deleting it).
func TestBlockAllowTTL(t *testing.T) {
	o := load(t)
	_ = o.SetConfig(defaultCfg())
	pkt := ip4("198.51.100.7", "203.0.113.1", 17, udp(4000, 5000, 10), 0)

	_ = o.PutPrefix("block", netip.MustParsePrefix("198.51.100.0/24"), 0)
	if r := run(t, o, pkt); r != xdpDrop {
		t.Fatalf("blocked: got %d", r)
	}
	_ = o.PutPrefix("allow", netip.MustParsePrefix("198.51.100.7/32"), 0)
	if r := run(t, o, pkt); r != xdpPass {
		t.Fatalf("allow must beat block: got %d", r)
	}
	_ = o.DelPrefix("allow", netip.MustParsePrefix("198.51.100.7/32"))

	_ = o.PutPrefix("block", netip.MustParsePrefix("198.51.100.0/24"), 0)
	_ = o.PutPrefix("block", netip.MustParsePrefix("198.51.100.0/24"), 50*time.Millisecond)
	if r := run(t, o, pkt); r != xdpDrop {
		t.Fatalf("ttl entry live: got %d", r)
	}
	time.Sleep(80 * time.Millisecond)
	if r := run(t, o, pkt); r != xdpPass {
		t.Fatalf("ttl entry must expire in-kernel: got %d", r)
	}
	n, _ := o.SweepExpired("block")
	if n != 1 {
		t.Fatalf("sweep removed %d", n)
	}
}

// Dry-run must PASS the packet yet still account it under its would-be drop reason.
func TestDryRun(t *testing.T) {
	o := load(t)
	c := defaultCfg()
	c.Flags |= FDryRun
	_ = o.SetConfig(c)
	_ = o.PutPrefix("block", netip.MustParsePrefix("198.51.100.0/24"), 0)
	pkt := ip4("198.51.100.7", "203.0.113.1", 17, udp(4000, 5000, 10), 0)
	if r := run(t, o, pkt); r != xdpPass {
		t.Fatalf("dry-run must pass: got %d", r)
	}
	st, _ := o.ReadStats()
	if st[RBlocklist].Pkts != 1 {
		t.Fatalf("dry-run must still account: %+v", st[RBlocklist])
	}
}

// Hygiene filters: amplification ports honour min-length (big DNS reply dropped,
// small one passes, NTP drops at any size), fragments, and invalid TCP flags/port 0.
func TestAmpFragSanity(t *testing.T) {
	o := load(t)
	_ = o.SetConfig(defaultCfg())
	_ = o.SetAmpPorts(map[uint16]uint16{53: 512, 123: 0})

	big := ip4("192.0.2.9", "203.0.113.1", 17, udp(53, 40000, 800), 0)
	small := ip4("192.0.2.9", "203.0.113.1", 17, udp(53, 40000, 100), 0)
	ntp := ip4("192.0.2.9", "203.0.113.1", 17, udp(123, 40000, 8), 0)
	if r := run(t, o, big); r != xdpDrop {
		t.Errorf("big DNS response: %d", r)
	}
	if r := run(t, o, small); r != xdpPass {
		t.Errorf("small DNS response must pass: %d", r)
	}
	if r := run(t, o, ntp); r != xdpDrop {
		t.Errorf("NTP src port 123: %d", r)
	}

	frag := ip4("192.0.2.9", "203.0.113.1", 17, make([]byte, 100), 0x00b9) // offset 185, no L4
	if r := run(t, o, frag); r != xdpDrop {
		t.Errorf("later fragment: %d", r)
	}
	first := ip4("192.0.2.9", "203.0.113.1", 17, udp(1000, 2000, 100), 0x2000)
	if r := run(t, o, first); r != xdpDrop {
		t.Errorf("first fragment: %d", r)
	}

	for name, f := range map[string]byte{"syn+fin": 0x03, "syn+rst": 0x06, "null": 0} {
		if r := run(t, o, ip4("192.0.2.9", "203.0.113.1", 6, tcp(1000, 80, f), 0)); r != xdpDrop {
			t.Errorf("%s: %d", name, r)
		}
	}
	if r := run(t, o, ip4("192.0.2.9", "203.0.113.1", 6, tcp(1000, 80, 0x02), 0)); r != xdpPass {
		t.Errorf("plain SYN: %d", r)
	}
	if r := run(t, o, ip4("192.0.2.9", "203.0.113.1", 6, tcp(1000, 0, 0x02), 0)); r != xdpDrop {
		t.Errorf("dport 0: %d", r)
	}
}

// ARP must pass untouched; a frame truncated inside the IPv4 header must be dropped as malformed.
func TestMalformedAndNonIP(t *testing.T) {
	o := load(t)
	_ = o.SetConfig(defaultCfg())
	arp := append(eth(0x0806), make([]byte, 28)...)
	if r := run(t, o, arp); r != xdpPass {
		t.Errorf("ARP must pass: %d", r)
	}
	trunc := ip4("192.0.2.9", "203.0.113.1", 17, udp(1, 2, 0), 0)[:30] // cuts IP header
	if r := run(t, o, append(trunc, make([]byte, 34)...)[:30]); r != xdpDrop {
		// test-run pads to 14 minimum only; a 30-byte frame has a truncated IPv4 header
		t.Errorf("truncated IPv4: %d", r)
	}
}

// Fingerprint rules: a matching packet is dropped, near-misses (wrong length or
// port) pass, counters are right, a shared rate-limit rule admits only its burst,
// and an expired rule no longer matches.
func TestFingerprintRules(t *testing.T) {
	o := load(t)
	_ = o.SetConfig(defaultCfg())
	rule := FPRule{
		Proto: 17, Action: FPDrop, Family: 4,
		SportLo: 0, SportHi: 65535, DportLo: 7777, DportHi: 7777,
		LenLo: 400, LenHi: 600, TTLLo: 0, TTLHi: 255,
	}
	if err := o.SetFPRules([]FPRule{rule}, nil); err != nil {
		t.Fatal(err)
	}
	hit := ip4("192.0.2.9", "203.0.113.1", 17, udp(9, 7777, 472), 0) // l3 = 20+8+472 = 500
	miss := ip4("192.0.2.9", "203.0.113.1", 17, udp(9, 7777, 100), 0)
	miss2 := ip4("192.0.2.9", "203.0.113.1", 17, udp(9, 7778, 472), 0)
	if r := run(t, o, hit); r != xdpDrop {
		t.Errorf("hit: %d", r)
	}
	if r := run(t, o, miss); r != xdpPass {
		t.Errorf("len miss: %d", r)
	}
	if r := run(t, o, miss2); r != xdpPass {
		t.Errorf("port miss: %d", r)
	}
	cs, _ := o.ReadFPCounters(1)
	if cs[0].MatchedPkts != 1 || cs[0].DroppedPkts != 1 {
		t.Errorf("counters %+v", cs[0])
	}

	// Shared rate-limit rule: burst 3, ~0 refill.
	rl := rule
	rl.Action = FPRateLimit
	rl.RatePPS, rl.Burst = 1, 3
	_ = o.SetFPRules([]FPRule{rl}, nil)
	pass := 0
	for i := 0; i < 10; i++ {
		if run(t, o, hit) == xdpPass {
			pass++
		}
	}
	if pass < 3 || pass > 4 {
		t.Errorf("fp ratelimit passed %d of 10, want ~3", pass)
	}

	// Expired rule must not match.
	ex := rule
	ex.ExpiresNS = NowNS() - 1
	_ = o.SetFPRules([]FPRule{ex}, nil)
	if r := run(t, o, hit); r != xdpPass {
		t.Errorf("expired rule matched: %d", r)
	}
}

// Per-source token buckets: each source gets an independent burst, and switching
// cfg.Attack tightens the limit for a source with no prior state.
func TestPerSourceRateLimit(t *testing.T) {
	o := load(t)
	c := defaultCfg()
	c.Lim[0][CUDP] = Limit{PPS: 1, Burst: 5}
	c.Lim[1][CUDP] = Limit{PPS: 1, Burst: 2}
	_ = o.SetConfig(c)
	a := ip4("192.0.2.50", "203.0.113.1", 17, udp(1000, 2000, 10), 0)
	b := ip4("192.0.2.51", "203.0.113.1", 17, udp(1000, 2000, 10), 0)
	count := func(p []byte) (n int) {
		for i := 0; i < 20; i++ {
			if run(t, o, p) == xdpPass {
				n++
			}
		}
		return
	}
	if n := count(a); n < 5 || n > 6 {
		t.Errorf("normal burst: %d passed, want ~5", n)
	}
	if n := count(b); n < 5 || n > 6 {
		t.Errorf("sources must have independent buckets: %d", n)
	}
	// Attack mode tightens the limit for a fresh source.
	c.Attack = 1
	_ = o.SetConfig(c)
	fresh := ip4("192.0.2.52", "203.0.113.1", 17, udp(1000, 2000, 10), 0)
	if n := count(fresh); n < 2 || n > 3 {
		t.Errorf("attack burst: %d passed, want ~2", n)
	}
}

// IPv6: neighbour discovery with hop limit 255 passes even from a blocked prefix,
// the same packet with hop limit 64 does not, and the v6 blocklist works.
func TestIPv6(t *testing.T) {
	o := load(t)
	_ = o.SetConfig(defaultCfg())
	ns := ip6("fe80::1", "ff02::1:ff00:2", 58, 255, []byte{135, 0, 0, 0, 0, 0, 0, 0})
	_ = o.PutPrefix("block", netip.MustParsePrefix("fe80::/10"), 0)
	if r := run(t, o, ns); r != xdpPass {
		t.Errorf("ND with hop limit 255 must pass even from a blocked prefix: %d", r)
	}
	nsRouted := ip6("fe80::1", "ff02::1:ff00:2", 58, 64, []byte{135, 0, 0, 0, 0, 0, 0, 0})
	if r := run(t, o, nsRouted); r != xdpDrop {
		t.Errorf("ND with hop limit 64 is not link-local: %d", r)
	}
	_ = o.PutPrefix("block", netip.MustParsePrefix("2001:db8:bad::/48"), 0)
	p := ip6("2001:db8:bad::5", "2001:db8::1", 17, 64, udp(1, 2, 10))
	if r := run(t, o, p); r != xdpDrop {
		t.Errorf("v6 blocklist: %d", r)
	}
	ok := ip6("2001:db8:900d::5", "2001:db8::1", 17, 64, udp(1, 2, 10))
	if r := run(t, o, ok); r != xdpPass {
		t.Errorf("v6 clean: %d", r)
	}
}

// With protected-only on, blocked sources are dropped only when aimed at the protected prefix.
func TestProtectedOnly(t *testing.T) {
	o := load(t)
	c := defaultCfg()
	c.Flags |= FProtectedOnly
	_ = o.SetConfig(c)
	_ = o.PutPrefix("protect", netip.MustParsePrefix("203.0.113.0/24"), 0)
	_ = o.PutPrefix("block", netip.MustParsePrefix("198.51.100.0/24"), 0)
	toProt := ip4("198.51.100.7", "203.0.113.9", 17, udp(1, 2, 10), 0)
	toOther := ip4("198.51.100.7", "192.0.2.77", 17, udp(1, 2, 10), 0)
	if r := run(t, o, toProt); r != xdpDrop {
		t.Errorf("to protected: %d", r)
	}
	if r := run(t, o, toOther); r != xdpPass {
		t.Errorf("to unprotected must be untouched: %d", r)
	}
}

// Sampling: with rate 1 every packet is sampled, DROPPED packets included, and the
// record carries the verdict reason and protocol.
func TestSamplingRingbuf(t *testing.T) {
	o := load(t)
	c := defaultCfg()
	c.SampleRate = 1
	_ = o.SetConfig(c)
	_ = o.PutPrefix("block", netip.MustParsePrefix("198.51.100.0/24"), 0)
	rd, err := ringbuf.NewReader(o.Samples)
	if err != nil {
		t.Fatal(err)
	}
	defer rd.Close()
	pkt := ip4("198.51.100.7", "203.0.113.1", 17, udp(4000, 5000, 10), 0)
	run(t, o, pkt)
	rd.SetDeadline(time.Now().Add(time.Second))
	rec, err := rd.Read()
	if err != nil {
		t.Fatalf("no sample (dropped packets must still be sampled): %v", err)
	}
	if len(rec.RawSample) != int(unsafe.Sizeof(Sample{})) {
		t.Fatalf("sample size %d", len(rec.RawSample))
	}
	var s Sample
	s.Reason = rec.RawSample[unsafe.Offsetof(s.Reason)]
	s.Proto = rec.RawSample[unsafe.Offsetof(s.Proto)]
	if int(s.Reason) != RBlocklist || s.Proto != 17 {
		t.Errorf("sample reason=%d proto=%d", s.Reason, s.Proto)
	}
}
