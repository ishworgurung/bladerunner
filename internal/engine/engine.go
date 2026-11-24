// Package engine is the control loop: it reads kernel counters and sampled
// packets, decides when the system is under attack, and pushes mitigations
// (tightened limits, fingerprint rules, source blocks) into the BPF maps.
package engine

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/cilium/ebpf/ringbuf"

	"github.com/ishworgurung/bladerunner/internal/bpf"
	"github.com/ishworgurung/bladerunner/internal/config"
	"github.com/ishworgurung/bladerunner/internal/detect"
	"github.com/ishworgurung/bladerunner/internal/metrics"
)

// activeRule is a fingerprint rule the engine is currently keeping installed.
// The kernel has its own copy with an absolute expiry; this copy lets the engine
// refresh, expire and re-rank rules.
type activeRule struct {
	action  uint8
	rate    float64
	pps     float64
	expires time.Time
}

// Engine owns all control-plane state. The mutex serialises three goroutines:
// the ring-buffer sampler (many Observe calls), the tick loop (analysis + map
// writes) and the metrics scrape. Map writes happen only while holding mu, which
// also makes read-modify-write of the single config entry race-free.
type Engine struct {
	cfg *config.Config
	o   *bpf.Objects
	log *slog.Logger

	// mu guards everything below it.
	mu    sync.Mutex
	det   *detect.Detector
	fp    *detect.Fingerprinter
	hh    *detect.HeavyHitters
	rules map[detect.Tuple]*activeRule
	// order[i] is the tuple installed in kernel slot i; used to label per-rule metrics.
	order []detect.Tuple // order of rules as installed (index = kernel slot)
	// last/lastAt: previous counter snapshot, for computing a rate over the tick.
	last   [bpf.NStat]bpf.Counter
	lastAt time.Time

	// Observability counters exported as metrics.
	offeredPPS  float64
	autoBlocks  uint64
	rulesPushed uint64
	attacks     uint64
}

// New builds an engine around an already-loaded program.
func New(cfg *config.Config, o *bpf.Objects, log *slog.Logger) *Engine {
	e := &Engine{cfg: cfg, o: o, log: log, rules: map[detect.Tuple]*activeRule{}}
	e.build()
	return e
}

// build (re)creates the analytics from the current config. Resets learned state.
func (e *Engine) build() {
	c := e.cfg
	e.det = &detect.Detector{Alpha: c.Detect.Alpha, TriggerFactor: c.Detect.TriggerFactor,
		MinPPS: c.Detect.MinPPS, ReleaseAfter: c.Detect.ReleaseAfter}
	e.fp = detect.NewFingerprinter(detect.FPConfig{
		MinTuplePPS: c.Fingerprint.MinTuplePPS, MinShare: c.Fingerprint.MinShare,
		RateFactor: c.Fingerprint.RateFactor, MinRatePPS: c.Fingerprint.MinRatePPS,
		BaselineAlpha: c.Fingerprint.BaselineAlpha}, c.SampleRate)
	e.hh = detect.NewHeavyHitters(c.HeavyHitter.PPS, c.HeavyHitter.Windows, c.SampleRate)
}

// Apply pushes the static configuration into the kernel. It is idempotent and is
// also what a SIGHUP reload runs: it adds and updates, it never removes (removal
// of a prefix is an explicit CLI action so a bad edit cannot silently unblock).
// The config entry is read first so runtime fields (FPN, Attack) are preserved.
func (e *Engine) Apply() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	prev, _ := e.o.GetConfig()
	if err := e.o.SetConfig(e.cfg.BPF(prev)); err != nil {
		return fmt.Errorf("config: %w", err)
	}
	for _, set := range []string{"protect", "allow", "block"} {
		for _, p := range e.cfg.Prefixes(set) {
			if err := e.o.PutPrefix(set, p, 0); err != nil {
				return fmt.Errorf("%s %s: %w", set, p, err)
			}
		}
	}
	return e.o.SetAmpPorts(e.cfg.AmpPorts)
}

// StaticPrefixes returns the prefixes of one set ("allow"|"block"|"protect") that
// come from the YAML file, so other writers (the Redis feed) never delete them.
func (e *Engine) StaticPrefixes(set string) []netip.Prefix {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.cfg.Prefixes(set)
}

// Reload swaps in a new config and re-applies it. Detector and baseline state restart.
func (e *Engine) Reload(c *config.Config) error {
	e.mu.Lock()
	e.cfg = c
	e.build()
	e.mu.Unlock()
	return e.Apply()
}

// Run blocks until ctx is cancelled. It starts the sampler goroutine, then drives
// the analysis loop on a ticker and a slower housekeeping loop on another.
// Run blocks until ctx is done.
func (e *Engine) Run(ctx context.Context) error {
	rd, err := ringbuf.NewReader(e.o.Samples)
	if err != nil {
		return fmt.Errorf("ringbuf: %w", err)
	}
	// Closing the reader on shutdown unblocks the sampler's Read.
	go func() { <-ctx.Done(); rd.Close() }()
	go e.sampler(rd)

	e.mu.Lock()
	e.lastAt = time.Now()
	// Prime the counter snapshot so the first tick computes a real delta, not a rate since boot.
	e.last, _ = e.o.ReadStats()
	interval := e.cfg.Detect.Interval
	e.mu.Unlock()

	tick := time.NewTicker(interval)
	defer tick.Stop()
	// Every 30s free expired blocklist entries (the data plane already ignores them).
	sweep := time.NewTicker(30 * time.Second)
	defer sweep.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case now := <-tick.C:
			e.tick(now)
		case <-sweep.C:
			n, _ := e.o.SweepExpired("block")
			if n > 0 {
				e.log.Info("swept expired blocks", "n", n)
			}
		}
	}
}

// sampler drains the ring buffer. It decodes each record with the machine's native
// endianness (the kernel wrote it in host order) and feeds both analyses under the lock.
func (e *Engine) sampler(rd *ringbuf.Reader) {
	for {
		rec, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			continue
		}
		var s bpf.Sample
		if err := binary.Read(bytes.NewReader(rec.RawSample), binary.NativeEndian, &s); err != nil {
			continue
		}
		e.mu.Lock()
		e.fp.Observe(&s)
		e.hh.Observe(&s)
		e.mu.Unlock()
	}
}

// tick runs once per detect.interval: measure offered load, update attack state,
// close the analysis window, and install whatever mitigation that produced.
func (e *Engine) tick(now time.Time) {
	e.mu.Lock()
	defer e.mu.Unlock()
	st, err := e.o.ReadStats()
	if err != nil {
		e.log.Error("read stats", "err", err)
		return
	}
	dt := now.Sub(e.lastAt)
	if dt <= 0 {
		return
	}
	// Offered load = sum of ALL reason counters' deltas (each packet is counted
	// exactly once), i.e. what arrived, not what was passed.
	var d uint64
	for i := 0; i < bpf.NReason; i++ {
		d += st[i].Pkts - e.last[i].Pkts
	}
	e.last, e.lastAt = st, now
	e.offeredPPS = float64(d) / dt.Seconds()

	// Detector transition. On change, flip cfg.attack so the data plane switches limit sets for every source at once.
	attack, changed := e.det.Update(e.offeredPPS, now)
	if changed {
		cfg, _ := e.o.GetConfig()
		cfg.Attack = 0
		if attack {
			cfg.Attack = 1
			e.attacks++
		}
		_ = e.o.SetConfig(cfg)
		e.log.Warn("attack state changed", "attack", attack,
			"offered_pps", int(e.offeredPPS), "baseline_pps", int(e.det.Baseline()))
	}

	// Close the analysis window. When fingerprinting is off we still flush to keep memory bounded and the baseline current.
	if e.cfg.Fingerprint.Enabled {
		cands := e.fp.Flush(dt, attack)
		e.mergeRules(cands, now)
	} else {
		e.fp.Flush(dt, false)
	}
	// Heavy hitters are evaluated every window, attack or not: a single huge source is worth blocking either way.
	hits := e.hh.Flush(dt)
	if e.cfg.HeavyHitter.Enabled {
		e.blockHeavy(hits)
	}
}

// mergeRules folds this window's candidates into the active set: new rules are
// added, existing ones get their lifetime refreshed (an attack that is still
// running keeps its rule), and rules whose traffic stopped are allowed to expire.
func (e *Engine) mergeRules(cands []detect.Candidate, now time.Time) {
	ttl := e.cfg.Fingerprint.RuleTTL
	dirty := false
	for _, c := range cands {
		r, ok := e.rules[c.Tuple]
		if !ok {
			r = &activeRule{}
			e.rules[c.Tuple] = r
			e.log.Warn("fingerprint rule", "tuple", fmt.Sprintf("%+v", c.Tuple),
				"action", actionName(c.Action), "pps", int(c.PPS), "rate", int(c.Rate))
			dirty = true
		}
		r.action, r.rate, r.pps, r.expires = c.Action, c.Rate, c.PPS, now.Add(ttl)
		// Refreshing the expiry rewrites the kernel entry as well, so the in-kernel deadline keeps moving while the attack lasts.
		dirty = true // expiry refreshed in kernel as well
	}
	for t, r := range e.rules {
		if now.After(r.expires) {
			delete(e.rules, t)
			dirty = true
		}
	}
	if dirty {
		e.installRules(now)
	}
}

// actionName is the log label for a rule action.
func actionName(a uint8) string {
	if a == bpf.FPDrop {
		return "drop"
	}
	return "ratelimit"
}

// installRules writes the active set to the kernel, highest-rate first, truncated
// to the table size. Each rule carries an absolute in-kernel expiry, so if the
// daemon dies the rules age out by themselves instead of lingering.
func (e *Engine) installRules(now time.Time) {
	type kv struct {
		t detect.Tuple
		r *activeRule
	}
	var list []kv
	for t, r := range e.rules {
		list = append(list, kv{t, r})
	}
	sort.Slice(list, func(i, j int) bool { return list[i].r.pps > list[j].r.pps })
	if len(list) > bpf.MaxFPRules {
		list = list[:bpf.MaxFPRules]
	}
	rules := make([]bpf.FPRule, len(list))
	e.order = e.order[:0]
	ttl := uint64(e.cfg.Fingerprint.RuleTTL)
	for i, x := range list {
		rules[i] = x.t.Rule(x.r.action, x.r.rate, bpf.NowNS()+ttl, uint32(i))
		e.order = append(e.order, x.t)
	}
	if err := e.o.SetFPRules(rules, nil); err != nil {
		e.log.Error("install rules", "err", err)
		return
	}
	e.rulesPushed++
}

// blockHeavy blocks heavy-hitter sources with a TTL. The per-tick cap bounds the
// blast radius if something (e.g. spoofed sources, a bad threshold) makes many
// sources look heavy at once. The allowlist still wins in the data plane.
func (e *Engine) blockHeavy(hits map[netip.Prefix]float64) {
	n := 0
	for p, pps := range hits {
		if n >= e.cfg.HeavyHitter.MaxPerTick {
			break
		}
		if err := e.o.PutPrefix("block", p, e.cfg.HeavyHitter.BlockTTL); err != nil {
			e.log.Error("auto-block", "prefix", p, "err", err)
			continue
		}
		e.autoBlocks++
		n++
		e.log.Warn("heavy hitter blocked", "prefix", p.String(), "pps", int(pps),
			"ttl", e.cfg.HeavyHitter.BlockTTL.String())
	}
}

// Collect snapshots current state as Prometheus metrics. Counters come straight
// from the kernel maps, so they stay correct even across a daemon restart.
func (e *Engine) Collect() *metrics.Set {
	e.mu.Lock()
	defer e.mu.Unlock()
	var m metrics.Set
	st, _ := e.o.ReadStats()
	for i := 0; i < bpf.NReason; i++ {
		m.Counter("bladerunner_packets_total", "Packets by verdict reason.", float64(st[i].Pkts), "reason", bpf.ReasonNames[i])
		m.Counter("bladerunner_bytes_total", "Bytes by verdict reason.", float64(st[i].Bytes), "reason", bpf.ReasonNames[i])
	}
	m.Counter("bladerunner_samples_total", "Samples delivered to userspace.", float64(st[bpf.SSampled].Pkts))
	m.Counter("bladerunner_samples_lost_total", "Samples lost (ring buffer full).", float64(st[bpf.SSampleLost].Pkts))
	cfg, _ := e.o.GetConfig()
	m.Gauge("bladerunner_attack", "1 while attack mode is active.", float64(cfg.Attack))
	m.Gauge("bladerunner_dry_run", "1 when running in dry-run mode.", float64(cfg.Flags&bpf.FDryRun))
	m.Gauge("bladerunner_offered_pps", "Offered load, packets/s (before drops).", e.offeredPPS)
	m.Gauge("bladerunner_baseline_pps", "Learned baseline load, packets/s.", e.det.Baseline())
	m.Gauge("bladerunner_fp_rules_active", "Active fingerprint rules.", float64(len(e.order)))
	m.Counter("bladerunner_attacks_total", "Attack episodes detected.", float64(e.attacks))
	m.Counter("bladerunner_autoblocks_total", "Sources auto-blocked as heavy hitters.", float64(e.autoBlocks))
	if fc, err := e.o.ReadFPCounters(len(e.order)); err == nil {
		for i, c := range fc {
			id := fmt.Sprint(i)
			m.Counter("bladerunner_fp_rule_matched_packets_total", "Packets matching a fingerprint rule.", float64(c.MatchedPkts), "rule", id)
			m.Counter("bladerunner_fp_rule_dropped_packets_total", "Packets dropped by a fingerprint rule.", float64(c.DroppedPkts), "rule", id)
		}
	}
	return &m
}
