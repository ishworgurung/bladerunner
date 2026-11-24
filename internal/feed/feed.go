// Package feed mirrors shared allow/block CIDR lists from Redis into the kernel
// maps. It is a one-way, best-effort source:
//
//   - Redis is only read; this package never writes to it.
//   - The packet path never waits on Redis. Everything here runs in the daemon.
//   - FAIL-OPEN: if Redis is unreachable, slow or returns garbage, nothing is
//     removed and nothing half-applied. The previous state stays and in-kernel
//     TTLs keep expiring on their own.
//
// Layout in Redis: one key per range, "<prefix>:<list>:<cidr>" with <list> being
// "allow" or "block". The key's Redis TTL becomes the in-kernel TTL.
package feed

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/ishworgurung/bladerunner/internal/config"
	"github.com/ishworgurung/bladerunner/internal/metrics"
)

// Lists are the sets that can be fed from Redis. "protect" is deliberately not
// one of them: it switches a global filtering mode, so it stays YAML-only.
var Lists = []string{"allow", "block"}

// Safety floors for BLOCK entries. A mistaken "0.0.0.0/0" or "10.0.0.0/4" in a
// shared list would otherwise cut off most of the Internet, so such broad ranges
// are refused. (Allow entries are not restricted: allowing more is the safe side.)
const (
	minBlockBitsV4 = 8
	minBlockBitsV6 = 16
	// The in-kernel allow tables hold 1024 entries per family.
	maxAllowEntries = 1000
)

// Sink is where entries go. *bpf.Objects implements it; tests use a fake.
type Sink interface {
	PutPrefix(set string, p netip.Prefix, ttl time.Duration) error
	DelPrefix(set string, p netip.Prefix) error
}

// Feed is one running Redis mirror.
type Feed struct {
	cfg    config.Redis
	rdb    *redis.Client
	sink   Sink
	log    *slog.Logger
	static func(set string) []netip.Prefix // YAML-owned prefixes: never deleted by the feed

	mu      sync.Mutex
	managed map[string]map[netip.Prefix]bool // entries this feed put, by list
	up      bool
	failing bool
	st      stats
}

type stats struct {
	syncs, errors, invalid, truncated, putErrors uint64
	lastOK                                       time.Time
	entries                                      map[string]int
}

// New builds a feed. It does not contact Redis (the connection is lazy), so a
// Redis that is down at startup cannot prevent the daemon from starting.
func New(c config.Redis, sink Sink, log *slog.Logger, static func(set string) []netip.Prefix) (*Feed, error) {
	opt := &redis.Options{
		Addr: c.Addr, Username: c.Username, DB: c.DB,
		DialTimeout: c.Timeout, ReadTimeout: c.Timeout, WriteTimeout: c.Timeout,
		MaxRetries: 1,
	}
	if c.PasswordEnv != "" {
		opt.Password = os.Getenv(c.PasswordEnv)
	}
	if c.TLS {
		t := &tls.Config{MinVersion: tls.VersionTLS12}
		if c.CAFile != "" {
			pem, err := os.ReadFile(c.CAFile)
			if err != nil {
				return nil, fmt.Errorf("redis ca_file: %w", err)
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(pem) {
				return nil, fmt.Errorf("redis ca_file %s: no certificates found", c.CAFile)
			}
			t.RootCAs = pool
		}
		opt.TLSConfig = t
	}
	if static == nil {
		static = func(string) []netip.Prefix { return nil }
	}
	return &Feed{cfg: c, rdb: redis.NewClient(opt), sink: sink, log: log, static: static,
		managed: map[string]map[netip.Prefix]bool{"allow": {}, "block": {}},
		st:      stats{entries: map[string]int{}}}, nil
}

// Close releases the Redis connection.
func (f *Feed) Close() error { return f.rdb.Close() }

// Run syncs immediately and then every poll_interval until ctx is cancelled.
func (f *Feed) Run(ctx context.Context) {
	f.SyncOnce(ctx)
	t := time.NewTicker(f.cfg.PollInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			f.SyncOnce(ctx)
		}
	}
}

// SyncOnce performs one full read-then-apply cycle. Both lists are read
// completely BEFORE anything is written to the kernel, so a Redis failure in the
// middle leaves the kernel untouched.
func (f *Feed) SyncOnce(ctx context.Context) error {
	want := map[string]map[netip.Prefix]time.Duration{}
	var invalid, truncated uint64
	for _, list := range Lists {
		m, inv, trunc, err := f.read(ctx, list)
		if err != nil {
			f.fail(err)
			return err
		}
		want[list] = m
		invalid += inv
		truncated += trunc
	}
	f.recover()
	f.apply(want, invalid, truncated)
	return nil
}

// fail records a failed sync. It logs only on the transition into failure, so an
// outage is one warning, not one per poll.
func (f *Feed) fail(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.st.syncs++
	f.st.errors++
	f.up = false
	if !f.failing {
		f.failing = true
		f.log.Warn("redis feed unavailable: keeping last known lists (fail-open)", "err", err)
	}
}

func (f *Feed) recover() {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failing {
		f.failing = false
		f.log.Info("redis feed recovered")
	}
}

// read scans one list and returns its valid entries with their remaining TTL
// (0 = permanent). It touches only keys under "<prefix>:<list>:".
func (f *Feed) read(ctx context.Context, list string) (map[netip.Prefix]time.Duration, uint64, uint64, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*f.cfg.Timeout+5*time.Second)
	defer cancel()
	pfx := f.cfg.KeyPrefix + ":" + list + ":"
	limit := f.cfg.MaxEntries
	if list == "allow" && limit > maxAllowEntries {
		limit = maxAllowEntries
	}
	out := map[netip.Prefix]time.Duration{}
	var invalid, truncated uint64

	var keys []string
	it := f.rdb.Scan(ctx, 0, pfx+"*", 1000).Iterator()
	for it.Next(ctx) {
		if len(keys) >= limit {
			truncated++
			continue
		}
		keys = append(keys, it.Val())
	}
	if err := it.Err(); err != nil {
		return nil, 0, 0, err
	}

	const batch = 500
	for i := 0; i < len(keys); i += batch {
		end := min(i+batch, len(keys))
		pipe := f.rdb.Pipeline()
		cmds := make([]*redis.DurationCmd, 0, end-i)
		for _, k := range keys[i:end] {
			cmds = append(cmds, pipe.PTTL(ctx, k))
		}
		if _, err := pipe.Exec(ctx); err != nil {
			return nil, 0, 0, err
		}
		for j, c := range cmds {
			ttl, err := c.Result()
			if err != nil {
				return nil, 0, 0, err
			}
			// go-redis maps the "-2 no such key" and "-1 no expiry" replies to
			// these negative durations.
			if ttl == -2 { // expired between SCAN and PTTL
				continue
			}
			p, ok := parse(list, strings.TrimPrefix(keys[i+j], pfx))
			if !ok {
				invalid++
				f.log.Warn("redis feed: ignoring invalid key", "key", keys[i+j])
				continue
			}
			if ttl < 0 { // -1: no TTL = permanent
				ttl = 0
			} else if ttl < time.Millisecond {
				ttl = time.Millisecond
			}
			out[p] = ttl
		}
	}
	return out, invalid, truncated, nil
}

// parse turns the CIDR part of a key into a masked prefix, applying the safety
// floor for block entries. A bare address becomes a /32 or /128.
func parse(list, s string) (netip.Prefix, bool) {
	p, err := netip.ParsePrefix(s)
	if err != nil {
		a, aerr := netip.ParseAddr(s)
		if aerr != nil {
			return netip.Prefix{}, false
		}
		p = netip.PrefixFrom(a, a.BitLen())
	}
	// IPv4-mapped IPv6 (::ffff:a.b.c.d/n) is stored in the IPv4 trie, where IPv4
	// packets are looked up: unmap it and shift the prefix length to match.
	if a := p.Addr(); a.Is4In6() {
		if p.Bits() < 96 {
			return netip.Prefix{}, false
		}
		p = netip.PrefixFrom(a.Unmap(), p.Bits()-96)
	}
	p = p.Masked()
	if !p.IsValid() {
		return netip.Prefix{}, false
	}
	if list == "block" {
		if (p.Addr().Is4() && p.Bits() < minBlockBitsV4) || (p.Addr().Is6() && p.Bits() < minBlockBitsV6) {
			return netip.Prefix{}, false
		}
	}
	return p, true
}

// apply writes the desired state to the sink and removes entries that this feed
// added earlier but that are no longer in Redis. It never removes an entry that
// the YAML config also lists.
func (f *Feed) apply(want map[string]map[netip.Prefix]time.Duration, invalid, truncated uint64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var putErrs uint64
	for _, list := range Lists {
		static := map[netip.Prefix]bool{}
		for _, p := range f.static(list) {
			static[p] = true
		}
		for p, ttl := range want[list] {
			// A prefix the YAML also lists is permanent there; a Redis TTL must not shorten it.
			if static[p] {
				continue
			}
			// A permanent entry that is already installed needs no rewrite.
			if ttl == 0 && f.managed[list][p] {
				continue
			}
			if err := f.sink.PutPrefix(list, p, ttl); err != nil {
				putErrs++
				f.log.Warn("redis feed: put failed", "list", list, "prefix", p, "err", err)
				continue
			}
			f.managed[list][p] = ttl == 0
		}
		for p := range f.managed[list] {
			if _, still := want[list][p]; still {
				continue
			}
			if !static[p] {
				if err := f.sink.DelPrefix(list, p); err != nil {
					putErrs++
					f.log.Warn("redis feed: delete failed", "list", list, "prefix", p, "err", err)
					continue
				}
			}
			delete(f.managed[list], p)
		}
		f.st.entries[list] = len(want[list])
	}
	f.st.syncs++
	f.st.invalid += invalid
	f.st.truncated += truncated
	f.st.putErrors += putErrs
	f.st.lastOK = time.Now()
	f.up = true
}

// Collect adds the feed's metrics to a Prometheus snapshot.
func (f *Feed) Collect(m *metrics.Set) {
	f.mu.Lock()
	defer f.mu.Unlock()
	up := 0.0
	if f.up {
		up = 1
	}
	m.Gauge("bladerunner_redis_up", "1 if the last Redis sync succeeded.", up)
	m.Counter("bladerunner_redis_syncs_total", "Redis sync attempts.", float64(f.st.syncs))
	m.Counter("bladerunner_redis_sync_errors_total", "Redis sync attempts that failed (state kept).", float64(f.st.errors))
	m.Counter("bladerunner_redis_invalid_keys_total", "Redis keys ignored as invalid or too broad.", float64(f.st.invalid))
	m.Counter("bladerunner_redis_truncated_total", "Redis keys ignored because a list hit max_entries.", float64(f.st.truncated))
	m.Counter("bladerunner_redis_apply_errors_total", "Kernel map writes that failed during a sync.", float64(f.st.putErrors))
	if !f.st.lastOK.IsZero() {
		m.Gauge("bladerunner_redis_last_sync_timestamp_seconds", "Unix time of the last successful sync.", float64(f.st.lastOK.Unix()))
	}
	for _, l := range Lists {
		m.Gauge("bladerunner_redis_entries", "Entries read from Redis, by list.", float64(f.st.entries[l]), "list", l)
	}
}
