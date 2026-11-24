// Package config defines the YAML configuration and converts it to the
// kernel-side representation.
package config

import (
	"fmt"
	"net/netip"
	"os"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/ishworgurung/bladerunner/internal/bpf"
)

// Limit is a user-facing token-bucket budget (packets/second and burst depth).
type Limit struct {
	PPS   uint32 `yaml:"pps"`
	Burst uint32 `yaml:"burst"`
}

// Limits groups the five traffic classes. Each source address gets an independent
// bucket per class, so e.g. a UDP flood does not consume its own SYN budget.
type Limits struct {
	Any  Limit `yaml:"any"`
	SYN  Limit `yaml:"syn"`
	UDP  Limit `yaml:"udp"`
	DNS  Limit `yaml:"dns"`
	ICMP Limit `yaml:"icmp"`
}

// Redis configures the optional shared-list feed. When enabled, the daemon
// periodically reads allow and block CIDR ranges from Redis and mirrors them into
// the kernel maps. Redis is only ever a SOURCE of data: the packet path never
// talks to it, and if it is unreachable the last known state simply stays in place
// (fail-open: no entry is removed because of an outage).
//
// Layout in Redis: one key per range, named "<key_prefix>:<list>:<cidr>", where
// <list> is "allow" or "block", e.g. "bladerunner:block:203.0.113.0/24". The value
// is free text (use it for a reason). The key's own Redis TTL becomes the in-kernel
// TTL; a key with no TTL is permanent until it is deleted from Redis.
type Redis struct {
	Enabled bool   `yaml:"enabled"`
	Addr    string `yaml:"addr"`
	// Username is optional (Redis 6+ ACL user).
	Username string `yaml:"username"`
	// PasswordEnv names the ENVIRONMENT VARIABLE holding the password, so the
	// secret never sits in the YAML file. Empty or unset variable = no password.
	PasswordEnv string `yaml:"password_env"`
	DB          int    `yaml:"db"`
	TLS         bool   `yaml:"tls"`
	// CAFile is a PEM bundle used to verify the server when tls is on; empty = system roots.
	CAFile       string        `yaml:"ca_file"`
	KeyPrefix    string        `yaml:"key_prefix"`
	PollInterval time.Duration `yaml:"poll_interval"`
	// Timeout bounds every network operation, so a hung Redis cannot stall the daemon.
	Timeout time.Duration `yaml:"timeout"`
	// MaxEntries caps how many ranges are read per list; extras are ignored and counted.
	MaxEntries int `yaml:"max_entries"`
}

// Config is the complete user configuration. It is deliberately flat and
// declarative: every field has a safe default (see Default) so a minimal file only
// needs the interface. Field names are the YAML keys.
type Config struct {
	// The interface to attach to.
	Interface string `yaml:"interface"`
	// native = driver XDP (fast, needs driver support); generic = works anywhere, slow.
	Mode string `yaml:"mode"` // native | generic
	// When true the program classifies and counts but never drops. Defaults to TRUE: observe first.
	DryRun bool `yaml:"dry_run"` // account but never drop
	// When true the XDP link is pinned so the filter keeps running if the daemon exits.
	Persist bool `yaml:"persist"` // keep XDP attached if the daemon exits
	// bpffs directory where maps/program are pinned so the `bladerunner` CLI can reach a running instance.
	PinDir string `yaml:"pin_dir"` // bpffs directory for CLI access
	// Prometheus listen address; empty disables the endpoint.
	Metrics string `yaml:"metrics"` // listen address, "" = off

	// Destinations to defend. Empty = filter everything. Non-empty = ignore all other destinations.
	Protected []string `yaml:"protected"` // destination prefixes to defend; empty = everything
	// Sources that are NEVER filtered. Checked first in the data plane.
	Allowlist []string `yaml:"allowlist"` // sources never filtered
	// Sources that are ALWAYS dropped.
	Blocklist []string `yaml:"blocklist"` // sources always dropped

	// Reflection-source ports -> minimum L3 length to drop (0 = drop any size).
	AmpPorts map[uint16]uint16 `yaml:"amp_ports"` // src port -> min L3 length (0 = any)
	// Drop IP fragments (rare at the edge, common in evasion).
	DropFragments bool `yaml:"drop_fragments"`
	// Drop NULL / SYN+FIN / SYN+RST and port-0 packets.
	Sanity bool `yaml:"sanity"`
	// Enable per-source token buckets.
	RateLimit bool `yaml:"rate_limit"`
	// Send 1-in-N packets to userspace for analysis; must be > 0 if fingerprinting or heavy-hitter blocking is on.
	SampleRate uint32 `yaml:"sample_rate"` // 1-in-N

	// Optional shared allow/block lists in Redis (off by default).
	Redis Redis `yaml:"redis"`

	// Per-source budgets: Normal applies in peacetime, Attack replaces it while an attack is detected.
	Limits struct {
		Normal Limits `yaml:"normal"`
		Attack Limits `yaml:"attack"`
	} `yaml:"limits"`

	// Attack detector tuning: see detect.Detector for the semantics of each field.
	Detect struct {
		Interval      time.Duration `yaml:"interval"`
		Alpha         float64       `yaml:"alpha"`
		TriggerFactor float64       `yaml:"trigger_factor"`
		MinPPS        float64       `yaml:"min_pps"`
		ReleaseAfter  time.Duration `yaml:"release_after"`
	} `yaml:"detect"`

	// Automatic fingerprint-rule generation.
	Fingerprint struct {
		Enabled       bool          `yaml:"enabled"`
		MinTuplePPS   float64       `yaml:"min_tuple_pps"`
		MinShare      float64       `yaml:"min_share"`
		RateFactor    float64       `yaml:"rate_factor"`
		MinRatePPS    float64       `yaml:"min_rate_pps"`
		BaselineAlpha float64       `yaml:"baseline_alpha"`
		RuleTTL       time.Duration `yaml:"rule_ttl"`
	} `yaml:"fingerprint"`

	// Automatic blocking of individual sources that stay above a rate.
	HeavyHitter struct {
		Enabled    bool          `yaml:"enabled"`
		PPS        float64       `yaml:"pps"`
		Windows    int           `yaml:"windows"`
		BlockTTL   time.Duration `yaml:"block_ttl"`
		MaxPerTick int           `yaml:"max_per_tick"`
	} `yaml:"heavy_hitter"`
}

// Default returns the built-in configuration. Choices worth knowing:
//   - DryRun is true, so a fresh deployment cannot drop traffic by accident.
//   - Amplification ports list well-known reflectors (NTP 123, SNMP 161, CLDAP 389,
//     SSDP 1900, memcached 11211, DNS 53 ...) with size thresholds that spare
//     ordinary small replies.
//   - Limits are ~10x typical per-client peaks; the attack set is 10x tighter.
func Default() *Config {
	c := &Config{
		Mode: "native", DryRun: true, PinDir: "/sys/fs/bpf/bladerunner",
		Metrics: "127.0.0.1:9100",
		AmpPorts: map[uint16]uint16{
			11: 0, 17: 0, 19: 0, 69: 0, 111: 0, 123: 200, 137: 0, 161: 200,
			389: 200, 1900: 300, 3702: 0, 5353: 0, 11211: 0, 53: 512,
		},
		DropFragments: true, Sanity: true, RateLimit: true, SampleRate: 128,
	}
	c.Limits.Normal = Limits{
		Any: Limit{0, 0}, SYN: Limit{2000, 4000}, UDP: Limit{20000, 40000},
		DNS: Limit{2000, 4000}, ICMP: Limit{200, 400},
	}
	c.Limits.Attack = Limits{
		Any: Limit{0, 0}, SYN: Limit{200, 400}, UDP: Limit{2000, 4000},
		DNS: Limit{200, 400}, ICMP: Limit{20, 40},
	}
	c.Redis = Redis{Addr: "127.0.0.1:6379", PasswordEnv: "BLADERUNNER_REDIS_PASSWORD",
		KeyPrefix: "bladerunner", PollInterval: 10 * time.Second, Timeout: 2 * time.Second, MaxEntries: 50000}
	c.Detect.Interval = time.Second
	c.Detect.Alpha = 0.05
	c.Detect.TriggerFactor = 3
	c.Detect.MinPPS = 100000
	c.Detect.ReleaseAfter = 30 * time.Second
	c.Fingerprint.Enabled = true
	c.Fingerprint.MinTuplePPS = 20000
	c.Fingerprint.MinShare = 0.10
	c.Fingerprint.RateFactor = 2
	c.Fingerprint.MinRatePPS = 1000
	c.Fingerprint.BaselineAlpha = 0.1
	c.Fingerprint.RuleTTL = 2 * time.Minute
	c.HeavyHitter.Enabled = true
	c.HeavyHitter.PPS = 20000
	c.HeavyHitter.Windows = 3
	c.HeavyHitter.BlockTTL = 10 * time.Minute
	c.HeavyHitter.MaxPerTick = 256
	return c
}

// Load reads a YAML file over the defaults, so omitted keys keep their default.
// KnownFields(true) makes unknown keys an error: a typo like "dryrun" must fail
// loudly instead of silently leaving protection in the wrong mode.
func Load(path string) (*Config, error) {
	c := Default()
	if path == "" {
		return c, c.Validate()
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	dec := yaml.NewDecoder(f)
	dec.KnownFields(true)
	if err := dec.Decode(c); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return c, c.Validate()
}

// prefixes parses CIDRs or bare addresses (a bare address becomes /32 or /128).
// Prefixes are masked so host bits cannot cause surprising LPM behaviour.
func prefixes(list []string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, s := range list {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			a, aerr := netip.ParseAddr(s)
			if aerr != nil {
				return nil, fmt.Errorf("bad prefix %q", s)
			}
			p = netip.PrefixFrom(a, a.BitLen())
		}
		out = append(out, p.Masked())
	}
	return out, nil
}

// Prefixes returns the parsed prefixes of one configured set ("protect"|"allow"|"block"). Validate has already rejected bad entries.
func (c *Config) Prefixes(set string) []netip.Prefix {
	var l []string
	switch set {
	case "protect":
		l = c.Protected
	case "allow":
		l = c.Allowlist
	case "block":
		l = c.Blocklist
	}
	p, _ := prefixes(l)
	return p
}

// Validate rejects configurations that would misbehave at runtime. It is called
// by Load and again after CLI overrides, so every path to the kernel is checked.
func (c *Config) Validate() error {
	for _, set := range [][]string{c.Protected, c.Allowlist, c.Blocklist} {
		if _, err := prefixes(set); err != nil {
			return err
		}
	}
	if c.Mode != "native" && c.Mode != "generic" {
		return fmt.Errorf("mode must be native or generic, got %q", c.Mode)
	}
	if c.Detect.Interval < 100*time.Millisecond {
		return fmt.Errorf("detect.interval must be >= 100ms")
	}
	if c.Detect.Alpha <= 0 || c.Detect.Alpha > 1 || c.Fingerprint.BaselineAlpha <= 0 || c.Fingerprint.BaselineAlpha > 1 {
		return fmt.Errorf("alpha values must be in (0,1]")
	}
	if c.Detect.TriggerFactor <= 1 {
		return fmt.Errorf("detect.trigger_factor must be > 1")
	}
	if c.HeavyHitter.Windows < 1 {
		return fmt.Errorf("heavy_hitter.windows must be >= 1")
	}
	if (c.Fingerprint.Enabled || c.HeavyHitter.Enabled) && c.SampleRate == 0 {
		return fmt.Errorf("sample_rate must be > 0 when fingerprinting or heavy-hitter blocking is enabled")
	}
	if r := c.Redis; r.Enabled {
		if r.Addr == "" || r.KeyPrefix == "" {
			return fmt.Errorf("redis.addr and redis.key_prefix must be set when redis is enabled")
		}
		if r.PollInterval < time.Second || r.Timeout < 50*time.Millisecond || r.Timeout > r.PollInterval {
			return fmt.Errorf("redis.poll_interval must be >= 1s and redis.timeout between 50ms and poll_interval")
		}
		if r.MaxEntries < 1 || r.MaxEntries > 262144 {
			return fmt.Errorf("redis.max_entries must be 1..262144")
		}
		if r.DB < 0 {
			return fmt.Errorf("redis.db must be >= 0")
		}
	}
	if len(c.AmpPorts) > 256 {
		return fmt.Errorf("at most 256 amp_ports")
	}
	return nil
}

// arr lays the named classes out in the index order the data plane expects (enum bladerunner_class).
func (l Limits) arr() (a [bpf.NClass]bpf.Limit) {
	a[bpf.CAny] = bpf.Limit{PPS: l.Any.PPS, Burst: l.Any.Burst}
	a[bpf.CSyn] = bpf.Limit{PPS: l.SYN.PPS, Burst: l.SYN.Burst}
	a[bpf.CUDP] = bpf.Limit{PPS: l.UDP.PPS, Burst: l.UDP.Burst}
	a[bpf.CDNS] = bpf.Limit{PPS: l.DNS.PPS, Burst: l.DNS.Burst}
	a[bpf.CICMP] = bpf.Limit{PPS: l.ICMP.PPS, Burst: l.ICMP.Burst}
	return
}

// BPF converts to the kernel-side struct. FPN and Attack are RUNTIME state owned
// by the engine, so they are carried over from prev rather than taken from YAML -
// otherwise a config reload would silently clear active mitigations.
// BPF converts to the kernel config. fpN and attack are runtime state and
// are carried over from prev.
func (c *Config) BPF(prev bpf.Config) bpf.Config {
	out := bpf.Config{SampleRate: c.SampleRate, FPN: prev.FPN, Attack: prev.Attack}
	if c.DryRun {
		out.Flags |= bpf.FDryRun
	}
	if c.DropFragments {
		out.Flags |= bpf.FDropFrags
	}
	if len(c.AmpPorts) > 0 {
		out.Flags |= bpf.FAmp
	}
	if len(c.Protected) > 0 {
		out.Flags |= bpf.FProtectedOnly
	}
	if c.RateLimit {
		out.Flags |= bpf.FRateLimit
	}
	if c.Sanity {
		out.Flags |= bpf.FSanity
	}
	out.Lim[0] = c.Limits.Normal.arr()
	out.Lim[1] = c.Limits.Attack.arr()
	return out
}
