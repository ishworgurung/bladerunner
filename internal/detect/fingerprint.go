package detect

import (
	"net/netip"
	"sort"
	"time"

	"github.com/ishworgurung/bladerunner/internal/bpf"
)

// Tuple is a generalised traffic signature, the unit in which attacks are
// described and baselines are kept. Packets are bucketed coarsely on purpose
// (length to 64 bytes, TTL to 16) so that the natural jitter of one attack stream
// collapses into one tuple, while unrelated traffic stays distinct.
type Tuple struct {
	Family, Proto uint8
	Sport, Dport  uint16
	LenBucket     uint16 // l3 length rounded down to 64
	TTLBucket     uint8  // ttl >> 4
	Flags         uint8  // TCP flags, exact
}

// FPConfig tunes fingerprint generation; see configs/bladerunner.yaml for the user-facing meaning of each field.
type FPConfig struct {
	MinTuplePPS   float64 // ignore tuples below this offered rate
	MinShare      float64 // ... or below this share of window traffic (0..1)
	RateFactor    float64 // existing tuples limited to baseline*factor
	MinRatePPS    float64 // floor for generated rate limits
	BaselineAlpha float64
}

// Candidate is a rule proposal produced when a window closes. The engine decides whether to install it.
type Candidate struct {
	Tuple  Tuple
	PPS    float64
	Action uint8   // bpf.FPDrop or bpf.FPRateLimit
	Rate   float64 // for FPRateLimit
}

// Fingerprinter aggregates sampled packets per window and maintains a per-tuple
// baseline learned while NOT under attack. The same type does both jobs so the
// "what is normal" and "what is anomalous" views are built from identical keys.
type Fingerprinter struct {
	Cfg        FPConfig
	SampleRate float64

	// baseline: smoothed packets/sec per tuple during normal operation. win/total: the window being accumulated.
	baseline map[Tuple]float64 // pps EWMA learned while not under attack
	win      map[Tuple]float64
	total    float64
}

// NewFingerprinter creates a fingerprinter. sampleRate is the kernel 1-in-N factor used to scale sample counts back up to packets.
func NewFingerprinter(c FPConfig, sampleRate uint32) *Fingerprinter {
	return &Fingerprinter{Cfg: c, SampleRate: float64(sampleRate),
		baseline: map[Tuple]float64{}, win: map[Tuple]float64{}}
}

// countable decides which sampled packets say something about traffic mix.
// Excluded: allowlisted, exempt, non-IP, out-of-scope, already-blocklisted and
// malformed packets. Packets that an existing fingerprint rule dropped ARE counted,
// so a working rule keeps seeing its own traffic and does not expire mid-attack.
func countable(r uint8) bool {
	switch int(r) {
	case bpf.RAllow, bpf.RExempt, bpf.RNonIP, bpf.RUnprot, bpf.RBlocklist, bpf.RMalformed:
		return false
	}
	return true
}

// tuples returns the two generalisations of a sample. Reflection floods have a
// fixed SOURCE port and random destination ports; direct floods to a service have
// a fixed DESTINATION port and random source ports. We cannot know which, so both
// views are counted and the one that concentrates traffic wins at flush time.
func tuples(s *bpf.Sample) (a, b Tuple) {
	base := Tuple{Family: s.Family, Proto: s.Proto, LenBucket: s.L3Len &^ 63, TTLBucket: s.TTL >> 4}
	if s.Proto == 6 {
		base.Flags = s.Flags
	}
	a, b = base, base
	if s.Proto == 6 || s.Proto == 17 {
		a.Sport = s.Sport
		b.Dport = s.Dport
	}
	return
}

// Observe adds one sample to the current window. Each sample is weighted by
// SampleRate so counts approximate real packet counts.
func (f *Fingerprinter) Observe(s *bpf.Sample) {
	if !countable(s.Reason) {
		return
	}
	a, b := tuples(s)
	f.win[a] += f.SampleRate
	if b != a {
		f.win[b] += f.SampleRate
	}
	f.total += f.SampleRate
}

// Flush closes the window.
//   - Not under attack: only learn - fold the window into the baseline, decaying
//     tuples that were not seen.
//   - Under attack: compare the window to the baseline and emit candidates.
func (f *Fingerprinter) Flush(window time.Duration, attack bool) []Candidate {
	sec := window.Seconds()
	var out []Candidate
	// LEARNING: tuples absent this window decay; seen tuples move toward their window rate (EWMA).
	if !attack {
		for t, v := range f.baseline {
			if _, ok := f.win[t]; !ok {
				f.baseline[t] = v * (1 - f.Cfg.BaselineAlpha)
				if f.baseline[t] < 0.5 {
					delete(f.baseline, t)
				}
			}
		}
		for t, n := range f.win {
			f.baseline[t] = f.Cfg.BaselineAlpha*(n/sec) + (1-f.Cfg.BaselineAlpha)*f.baseline[t]
		}
		// MITIGATING: only tuples that are both large in absolute rate and in share of traffic qualify, to avoid acting on noise.
	} else if f.total > 0 {
		totalPPS := f.total / sec
		for t, n := range f.win {
			pps := n / sec
			if pps < f.Cfg.MinTuplePPS || pps/totalPPS < f.Cfg.MinShare {
				continue
			}
			// Never seen (or negligible) in the baseline => a brand-new traffic class => DROP.
			// Known but far above its normal rate => shared RATE LIMIT at a multiple of the
			// baseline, so legitimate flows of that class still get through.
			base, known := f.baseline[t]
			c := Candidate{Tuple: t, PPS: pps}
			switch {
			case !known || base < 1:
				c.Action = bpf.FPDrop
			case pps > base*f.Cfg.RateFactor:
				c.Action = bpf.FPRateLimit
				c.Rate = base * f.Cfg.RateFactor
				if c.Rate < f.Cfg.MinRatePPS {
					c.Rate = f.Cfg.MinRatePPS
				}
			default:
				continue
			}
			out = append(out, c)
		}
		sort.Slice(out, func(i, j int) bool { return out[i].PPS > out[j].PPS })
		// Collapse the sport-view and dport-view of the same packets into one rule so
		// rule slots (only 32) are not wasted on duplicates.
		out = dedupe(out)
	}
	f.win = map[Tuple]float64{}
	f.total = 0
	return out
}

// dedupe drops the second view of the same traffic: when the sport-view and
// dport-view of a tuple carry (nearly) the same packet rate they describe the same
// packets, and one rule is enough. Input must be sorted by PPS descending.
func dedupe(in []Candidate) []Candidate {
	var out []Candidate
	for _, c := range in {
		dup := false
		for _, s := range out {
			a, b := s.Tuple, c.Tuple
			a.Sport, a.Dport, b.Sport, b.Dport = 0, 0, 0, 0
			if a == b && s.Action == c.Action && c.PPS >= 0.9*s.PPS {
				dup = true
				break
			}
		}
		if !dup {
			out = append(out, c)
		}
	}
	return out
}

// BaselineSize is for diagnostics and tests.
func (f *Fingerprinter) BaselineSize() int { return len(f.baseline) }

// Rule converts a tuple into a kernel rule. The wildcarded port becomes the full
// 0..65535 range, length and TTL become their bucket ranges, and TCP flags must
// match exactly. Because a DROP is only emitted for traffic classes absent from the
// baseline, a generalised rule does not hit known-good flows.
func (t Tuple) Rule(action uint8, rate float64, expires uint64, id uint32) bpf.FPRule {
	r := bpf.FPRule{
		ExpiresNS: expires, Action: action, Family: t.Family, Proto: t.Proto,
		SportLo: 0, SportHi: 65535, DportLo: 0, DportHi: 65535,
		LenLo: t.LenBucket, LenHi: t.LenBucket + 63,
		TTLLo: t.TTLBucket << 4, TTLHi: t.TTLBucket<<4 | 15, ID: id,
	}
	if t.Sport != 0 {
		r.SportLo, r.SportHi = t.Sport, t.Sport
	}
	if t.Dport != 0 {
		r.DportLo, r.DportHi = t.Dport, t.Dport
	}
	if t.Proto == 6 {
		r.TCPFlagsMask, r.TCPFlagsVal = 0xFF, t.Flags
	}
	if action == bpf.FPRateLimit {
		r.RatePPS = uint32(rate)
		r.Burst = uint32(rate/10) + 1
	}
	return r
}

// ---------------------------------------------------------------- heavy hitters

// HeavyHitters finds individual sources that stay above a rate for several
// consecutive windows. Requiring persistence (Windows) avoids blocking a source
// for a one-off burst.
type HeavyHitters struct {
	ThresholdPPS float64
	Windows      int // consecutive windows above threshold before blocking
	SampleRate   float64

	cur    map[netip.Prefix]float64
	streak map[netip.Prefix]int
}

func NewHeavyHitters(pps float64, windows int, sampleRate uint32) *HeavyHitters {
	return &HeavyHitters{ThresholdPPS: pps, Windows: windows, SampleRate: float64(sampleRate),
		cur: map[netip.Prefix]float64{}, streak: map[netip.Prefix]int{}}
}

// SourcePrefix is the unit of attribution: a /32 for IPv4 and a /64 for IPv6
// (one IPv6 subscriber typically owns a whole /64, so blocking one /128 is useless).
func SourcePrefix(s *bpf.Sample) netip.Prefix {
	var b [4]byte
	if s.Family == 4 {
		nativeBytes(s.Saddr[0], b[:])
		return netip.PrefixFrom(netip.AddrFrom4(b), 32)
	}
	var a [16]byte
	for i := 0; i < 4; i++ {
		nativeBytes(s.Saddr[i], a[i*4:])
	}
	return netip.PrefixFrom(netip.AddrFrom16(a), 64).Masked()
}

// Observe accumulates per-source weight for the current window.
func (h *HeavyHitters) Observe(s *bpf.Sample) {
	if !countable(s.Reason) {
		return
	}
	h.cur[SourcePrefix(s)] += h.SampleRate
}

// Flush returns the sources that exceeded the threshold for the required number of
// consecutive windows, with their estimated rates. A source that dips below the
// threshold has its streak reset; returned sources are removed from tracking so
// they are not re-reported every window.
func (h *HeavyHitters) Flush(window time.Duration) map[netip.Prefix]float64 {
	sec := window.Seconds()
	out := map[netip.Prefix]float64{}
	for p, n := range h.cur {
		if pps := n / sec; pps >= h.ThresholdPPS {
			h.streak[p]++
			if h.streak[p] >= h.Windows {
				out[p] = pps
				delete(h.streak, p)
			}
		} else {
			delete(h.streak, p)
		}
	}
	for p := range h.streak {
		if _, ok := h.cur[p]; !ok {
			delete(h.streak, p)
		}
	}
	h.cur = map[netip.Prefix]float64{}
	return out
}
