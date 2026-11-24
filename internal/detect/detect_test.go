package detect

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"

	"github.com/ishworgurung/bladerunner/internal/bpf"
)

// Walks the detector through: quiet period (no false positive), a rise below the
// absolute floor (ignored), a real spike (detected), baseline frozen during the
// attack, early release refused, timer reset by a blip, and finally release.
func TestDetectorHysteresis(t *testing.T) {
	d := &Detector{Alpha: 0.2, TriggerFactor: 3, MinPPS: 1000, ReleaseAfter: 5 * time.Second}
	t0 := time.Unix(0, 0)
	at := func(i int) time.Time { return t0.Add(time.Duration(i) * time.Second) }
	for i := 0; i < 20; i++ {
		if a, _ := d.Update(500, at(i)); a {
			t.Fatalf("false positive at i=%d", i)
		}
	}
	// 800 pps is 1.6x baseline and below MinPPS floor: no trigger.
	if a, _ := d.Update(800, at(20)); a {
		t.Fatal("floor ignored")
	}
	if a, ch := d.Update(50000, at(21)); !a || !ch {
		t.Fatal("attack not detected")
	}
	base := d.Baseline()
	for i := 22; i < 30; i++ {
		d.Update(50000, at(i))
	}
	if d.Baseline() != base {
		t.Fatal("baseline learned from attack traffic")
	}
	// Quiet but not long enough.
	for i := 30; i < 34; i++ {
		if a, _ := d.Update(400, at(i)); !a {
			t.Fatalf("released early at %d", i)
		}
	}
	// A blip resets the release timer.
	d.Update(50000, at(34))
	for i := 35; i < 39; i++ {
		if a, _ := d.Update(400, at(i)); !a {
			t.Fatalf("timer not reset at %d", i)
		}
	}
	if a, ch := d.Update(400, at(40)); a || !ch {
		t.Fatal("not released")
	}
}

// sample builds a synthetic sampled packet from a given source with the supplied shape and verdict reason.
func sample(sport, dport, l3 uint16, proto uint8, reason int, src netip.Addr) *bpf.Sample {
	s := &bpf.Sample{Sport: sport, Dport: dport, L3Len: l3, Proto: proto, Family: 4, TTL: 60, Reason: uint8(reason)}
	a := src.As4()
	s.Saddr[0] = binary.NativeEndian.Uint32(a[:])
	return s
}

// Learn normal HTTPS + DNS traffic, then attack with (a) an NTP-style flood of a
// brand-new tuple -> must become a DROP, (b) a 100x DNS flood of a KNOWN tuple ->
// must become a RATE LIMIT, while the normal HTTPS tuple must never be selected.
func TestFingerprintBaselineVsNew(t *testing.T) {
	f := NewFingerprinter(FPConfig{MinTuplePPS: 100, MinShare: 0.05, RateFactor: 2, MinRatePPS: 50, BaselineAlpha: 0.5}, 10)
	src := netip.MustParseAddr("192.0.2.1")
	// Learn: normal HTTPS-like TCP traffic and DNS responses.
	for w := 0; w < 5; w++ {
		for i := 0; i < 200; i++ {
			f.Observe(sample(40000+uint16(i), 443, 100, 6, bpf.RPass, src))
		}
		for i := 0; i < 50; i++ {
			f.Observe(sample(53, 30000+uint16(i), 120, 17, bpf.RPass, src))
		}
		if c := f.Flush(time.Second, false); len(c) != 0 {
			t.Fatal("candidates while not under attack")
		}
	}
	// Attack: NTP reflection (new tuple, sport 123, large) + DNS flood (known tuple, 100x).
	for i := 0; i < 1000; i++ {
		f.Observe(sample(123, uint16(1024+i), 468, 17, bpf.RPass, src))
	}
	for i := 0; i < 600; i++ {
		f.Observe(sample(53, uint16(1024+i), 120, 17, bpf.RPass, src))
	}
	for i := 0; i < 100; i++ {
		f.Observe(sample(40000+uint16(i), 443, 100, 6, bpf.RPass, src))
	}
	c := f.Flush(time.Second, true)
	var gotNTP, gotDNS bool
	for _, x := range c {
		switch {
		case x.Tuple.Sport == 123 && x.Action == bpf.FPDrop:
			gotNTP = true
		case x.Tuple.Sport == 53 && x.Action == bpf.FPRateLimit:
			gotDNS = true
			if x.Rate < 50 || x.Rate > 1000 {
				t.Errorf("dns rate %v", x.Rate)
			}
		case x.Tuple.Dport == 443:
			t.Errorf("legit tuple selected: %+v", x)
		}
	}
	if !gotNTP || !gotDNS {
		t.Fatalf("ntp=%v dns=%v candidates=%+v", gotNTP, gotDNS, c)
	}
	if c[0].PPS < c[len(c)-1].PPS {
		t.Error("not sorted")
	}
	// The NTP flood has random dports: exactly one rule (sport view), not two.
	n := 0
	for _, x := range c {
		if x.Tuple.LenBucket == 448 {
			n++
		}
	}
	if n != 1 {
		t.Errorf("want 1 rule for the NTP flood, got %d", n)
	}
}

// Traffic already dropped by the blocklist must never generate fingerprint rules.
func TestFingerprintIgnoresAlreadyBlocked(t *testing.T) {
	f := NewFingerprinter(FPConfig{MinTuplePPS: 10, MinShare: 0.01, RateFactor: 2, MinRatePPS: 50, BaselineAlpha: 0.5}, 1)
	for i := 0; i < 5000; i++ {
		f.Observe(sample(1, 2, 100, 17, bpf.RBlocklist, netip.MustParseAddr("192.0.2.1")))
	}
	if c := f.Flush(time.Second, true); len(c) != 0 {
		t.Fatal("blocklisted traffic must not produce rules")
	}
}

// Tuple -> kernel rule: wildcard ports, length/TTL bucket ranges, exact TCP flags and rate-limit burst.
func TestRuleConversion(t *testing.T) {
	tp := Tuple{Family: 4, Proto: 17, Sport: 123, LenBucket: 448, TTLBucket: 3}
	r := tp.Rule(bpf.FPDrop, 0, 0, 7)
	if r.SportLo != 123 || r.SportHi != 123 || r.DportLo != 0 || r.DportHi != 65535 ||
		r.LenLo != 448 || r.LenHi != 511 || r.TTLLo != 48 || r.TTLHi != 63 {
		t.Fatalf("%+v", r)
	}
	tp = Tuple{Family: 4, Proto: 6, Dport: 80, Flags: 2}
	r = tp.Rule(bpf.FPRateLimit, 1000, 0, 1)
	if r.TCPFlagsMask != 0xFF || r.TCPFlagsVal != 2 || r.RatePPS != 1000 || r.Burst != 101 {
		t.Fatalf("%+v", r)
	}
}

// A source must stay above threshold for N consecutive windows; a quiet window resets the streak; benign sources are never selected.
func TestHeavyHitters(t *testing.T) {
	h := NewHeavyHitters(1000, 3, 10)
	bad := netip.MustParseAddr("203.0.113.66")
	ok := netip.MustParseAddr("203.0.113.67")
	for w := 0; w < 3; w++ {
		for i := 0; i < 200; i++ { // 200 samples * 10 = 2000 pps
			h.Observe(sample(1, 2, 100, 17, bpf.RPass, bad))
		}
		for i := 0; i < 20; i++ {
			h.Observe(sample(1, 2, 100, 17, bpf.RPass, ok))
		}
		out := h.Flush(time.Second)
		if w < 2 && len(out) != 0 {
			t.Fatalf("blocked after %d windows", w+1)
		}
		if w == 2 {
			if _, hit := out[netip.PrefixFrom(bad, 32)]; !hit || len(out) != 1 {
				t.Fatalf("got %v", out)
			}
		}
	}
	// A burst that stops resets the streak.
	for i := 0; i < 200; i++ {
		h.Observe(sample(1, 2, 100, 17, bpf.RPass, bad))
	}
	h.Flush(time.Second)
	h.Flush(time.Second)
	for i := 0; i < 200; i++ {
		h.Observe(sample(1, 2, 100, 17, bpf.RPass, bad))
	}
	if out := h.Flush(time.Second); len(out) != 0 {
		t.Fatal("streak not reset")
	}
}

// IPv6 sources are attributed to their /64, reconstructed correctly from the native-endian sample words.
func TestSourcePrefixV6(t *testing.T) {
	a := netip.MustParseAddr("2001:db8:1:2:aaaa:bbbb:cccc:dddd").As16()
	s := &bpf.Sample{Family: 6}
	for i := 0; i < 4; i++ {
		s.Saddr[i] = binary.NativeEndian.Uint32(a[i*4:])
	}
	if p := SourcePrefix(s); p != netip.MustParsePrefix("2001:db8:1:2::/64") {
		t.Fatalf("%v", p)
	}
}
