package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ishworgurung/bladerunner/internal/bpf"
)

// write stores YAML in a temp file and returns its path.
func write(t *testing.T, s string) string {
	p := filepath.Join(t.TempDir(), "c.yaml")
	if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// The built-in config must validate and must start in dry-run (safe by default).
func TestDefaultsValidAndDryRun(t *testing.T) {
	c := Default()
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if !c.DryRun {
		t.Fatal("default must be dry-run")
	}
}

// YAML overlays the defaults (unset keys keep defaults), bare addresses become
// host prefixes, and conversion to the kernel struct preserves runtime fields.
func TestLoadOverlayAndConvert(t *testing.T) {
	p := write(t, `
interface: eth0
dry_run: false
protected: [203.0.113.0/24, 2001:db8::/32]
allowlist: [192.0.2.1]
detect: {interval: 500ms, min_pps: 5000}
limits: {attack: {syn: {pps: 10, burst: 20}}}
`)
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.Detect.Interval.Milliseconds() != 500 || c.Detect.MinPPS != 5000 || c.Detect.TriggerFactor != 3 {
		t.Fatalf("overlay wrong: %+v", c.Detect)
	}
	b := c.BPF(bpf.Config{FPN: 3, Attack: 1})
	if b.Flags&bpf.FDryRun != 0 || b.Flags&bpf.FProtectedOnly == 0 || b.FPN != 3 || b.Attack != 1 {
		t.Fatalf("%+v", b)
	}
	if b.Lim[1][bpf.CSyn] != (bpf.Limit{PPS: 10, Burst: 20}) {
		t.Fatalf("%+v", b.Lim[1])
	}
	if got := c.Prefixes("allow"); len(got) != 1 || got[0].Bits() != 32 {
		t.Fatalf("bare address should become /32: %v", got)
	}
}

// Typos and nonsense must fail loudly instead of silently weakening protection.
func TestRejects(t *testing.T) {
	for name, y := range map[string]string{
		"typo key":    "dryrun: true\n",
		"bad prefix":  "blocklist: [not-an-ip]\n",
		"bad mode":    "mode: offload\n",
		"no sampling": "sample_rate: 0\n",
		"factor":      "detect: {trigger_factor: 1}\n",
	} {
		if _, err := Load(write(t, y)); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestRedisDefaultsAndValidation(t *testing.T) {
	c := Default()
	if c.Redis.Enabled {
		t.Fatal("redis must be off by default")
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("defaults must validate: %v", err)
	}
	c.Redis.Enabled = true
	if err := c.Validate(); err != nil {
		t.Fatalf("enabled defaults must validate: %v", err)
	}
	for name, mut := range map[string]func(*Config){
		"empty addr":   func(c *Config) { c.Redis.Addr = "" },
		"fast poll":    func(c *Config) { c.Redis.PollInterval = 100 * time.Millisecond },
		"timeout>poll": func(c *Config) { c.Redis.Timeout = time.Minute },
		"zero entries": func(c *Config) { c.Redis.MaxEntries = 0 },
		"too many":     func(c *Config) { c.Redis.MaxEntries = 1 << 20 },
		"negative db":  func(c *Config) { c.Redis.DB = -1 },
	} {
		cc := Default()
		cc.Redis.Enabled = true
		mut(cc)
		if cc.Validate() == nil {
			t.Errorf("%s: expected a validation error", name)
		}
	}
}

func writeFile(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// A good config is used as is; a broken one falls back to the last known-good copy.
func TestLoadWithFallback(t *testing.T) {
	d := t.TempDir()
	good := writeFile(t, d, "good.yaml", "interface: eth9\nmode: generic\n")
	bad := writeFile(t, d, "bad.yaml", "interface: eth0\nmodee: native\n") // unknown key
	last := filepath.Join(d, "state", "last-good.yaml")

	if _, used, err := LoadWithFallback(good, last); err != nil || used {
		t.Fatalf("good config: used=%v err=%v", used, err)
	}
	if err := SaveLastGood(good, last); err != nil {
		t.Fatal(err)
	}
	c, used, err := LoadWithFallback(bad, last)
	if err != nil || !used || c.Interface != "eth9" {
		t.Fatalf("bad config should fall back to last-good: used=%v err=%v cfg=%+v", used, err, c)
	}
	if _, _, err := LoadWithFallback(filepath.Join(d, "missing.yaml"), last); err != nil {
		t.Errorf("a missing file should also fall back: %v", err)
	}
	if _, _, err := LoadWithFallback(bad, ""); err == nil {
		t.Error("with no last-good copy a bad config must be an error")
	}
	if _, _, err := LoadWithFallback(bad, filepath.Join(d, "nope.yaml")); err == nil {
		t.Error("with a missing last-good copy a bad config must be an error")
	}
}

// If the saved copy is itself unusable, say so rather than hiding the original error.
func TestLoadWithFallbackReportsBothFailures(t *testing.T) {
	d := t.TempDir()
	bad := writeFile(t, d, "bad.yaml", "nonsense: [")
	last := writeFile(t, d, "last.yaml", "also: [bad")
	_, _, err := LoadWithFallback(bad, last)
	if err == nil || !strings.Contains(err.Error(), "unusable too") {
		t.Fatalf("expected both failures in the error, got %v", err)
	}
}

func TestSaveLastGoodIsAtomicAndPrivate(t *testing.T) {
	d := t.TempDir()
	src := writeFile(t, d, "c.yaml", "interface: eth1\n")
	dst := filepath.Join(d, "a", "b", "last-good.yaml")
	if err := SaveLastGood(src, dst); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(dst)
	if string(got) != "interface: eth1\n" {
		t.Errorf("copy differs: %q", got)
	}
	st, _ := os.Stat(dst)
	if st.Mode().Perm() != 0o640 {
		t.Errorf("mode = %v, want 0640", st.Mode().Perm())
	}
	entries, _ := os.ReadDir(filepath.Dir(dst))
	if len(entries) != 1 {
		t.Errorf("a temporary file was left behind: %v", entries)
	}
	if err := SaveLastGood("", dst); err != nil {
		t.Errorf("no source file (defaults) must be a no-op: %v", err)
	}
}
