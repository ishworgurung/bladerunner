package feed

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/ishworgurung/bladerunner/internal/config"
	"github.com/ishworgurung/bladerunner/internal/metrics"
)

// These tests talk to a REAL Redis. Point BLADERUNNER_TEST_REDIS at one
// ("host:port"), or let the test start a throwaway container with Docker
// (redis 7 alpine, pinned by digest). With neither available the tests are skipped.

type fakeSink struct {
	mu   sync.Mutex
	sets map[string]map[netip.Prefix]time.Duration
}

func newSink() *fakeSink {
	return &fakeSink{sets: map[string]map[netip.Prefix]time.Duration{"allow": {}, "block": {}}}
}
func (s *fakeSink) PutPrefix(set string, p netip.Prefix, ttl time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sets[set][p] = ttl
	return nil
}
func (s *fakeSink) DelPrefix(set string, p netip.Prefix) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sets[set], p)
	return nil
}
func (s *fakeSink) has(set, p string) (time.Duration, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.sets[set][netip.MustParsePrefix(p)]
	return d, ok
}
func (s *fakeSink) count(set string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.sets[set])
}

// Pinned by digest (redis 7 alpine) so a moved tag cannot change what the tests run.
const redisImage = "redis@sha256:7f7d30b7fdd09467bac58198a1f166dd69789d348d4fe859cccb20e0cf287fbe"

type server struct {
	addr, name string
}

func freePort(t *testing.T) int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func startRedis(t *testing.T) *server {
	t.Helper()
	if a := os.Getenv("BLADERUNNER_TEST_REDIS"); a != "" {
		return &server{addr: a}
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("no BLADERUNNER_TEST_REDIS and no docker: skipping")
	}
	port := freePort(t)
	name := fmt.Sprintf("bladerunner-test-redis-%d", port)
	out, err := exec.Command("docker", "run", "-d", "--name", name,
		"-p", fmt.Sprintf("127.0.0.1:%d:6379", port), redisImage).CombinedOutput()
	if err != nil {
		t.Skipf("cannot start redis container: %v: %s", err, out)
	}
	t.Cleanup(func() { exec.Command("docker", "rm", "-f", name).Run() })
	s := &server{addr: fmt.Sprintf("127.0.0.1:%d", port), name: name}
	c := redis.NewClient(&redis.Options{Addr: s.addr})
	defer c.Close()
	for i := 0; i < 100; i++ {
		if c.Ping(context.Background()).Err() == nil {
			return s
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("redis did not come up")
	return nil
}

func (s *server) client(t *testing.T) *redis.Client {
	c := redis.NewClient(&redis.Options{Addr: s.addr})
	t.Cleanup(func() { c.Close() })
	return c
}

func testCfg(addr string) config.Redis {
	return config.Redis{Enabled: true, Addr: addr, KeyPrefix: "t", PollInterval: time.Second,
		Timeout: 500 * time.Millisecond, MaxEntries: 1000}
}

func newFeed(t *testing.T, addr string, sink Sink, static func(string) []netip.Prefix) *Feed {
	t.Helper()
	f, err := New(testCfg(addr), sink, slog.New(slog.NewTextHandler(io.Discard, nil)), static)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	return f
}

func TestSyncAddsTTLsAndRemoves(t *testing.T) {
	srv := startRedis(t)
	rc := srv.client(t)
	ctx := context.Background()
	rc.FlushAll(ctx)
	rc.Set(ctx, "t:block:203.0.113.0/24", "scanner", 0)
	rc.Set(ctx, "t:block:198.51.100.7", "bare address", 0)
	rc.Set(ctx, "t:block:2001:db8::/32", "v6", 0)
	rc.Set(ctx, "t:block:192.0.2.0/24", "with ttl", 90*time.Second)
	rc.Set(ctx, "t:allow:10.1.2.0/24", "office", 0)

	sink := newSink()
	f := newFeed(t, srv.addr, sink, nil)
	if err := f.SyncOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok := sink.has("block", "203.0.113.0/24"); !ok {
		t.Error("block range missing")
	}
	if d, ok := sink.has("block", "198.51.100.7/32"); !ok || d != 0 {
		t.Errorf("bare address should become permanent /32, got %v %v", d, ok)
	}
	if _, ok := sink.has("block", "2001:db8::/32"); !ok {
		t.Error("v6 block missing")
	}
	if d, ok := sink.has("block", "192.0.2.0/24"); !ok || d <= 80*time.Second || d > 90*time.Second {
		t.Errorf("redis TTL should carry over (~90s), got %v %v", d, ok)
	}
	if _, ok := sink.has("allow", "10.1.2.0/24"); !ok {
		t.Error("allow range missing")
	}

	// Deleting the key in Redis removes the entry on the next sync.
	rc.Del(ctx, "t:block:203.0.113.0/24")
	if err := f.SyncOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok := sink.has("block", "203.0.113.0/24"); ok {
		t.Error("deleted key should be removed from the kernel set")
	}
	if _, ok := sink.has("block", "198.51.100.7/32"); !ok {
		t.Error("untouched entry must remain")
	}
}

func TestKeyExpiryRemovesEntry(t *testing.T) {
	srv := startRedis(t)
	rc := srv.client(t)
	ctx := context.Background()
	rc.FlushAll(ctx)
	rc.Set(ctx, "t:block:192.0.2.0/24", "x", 1200*time.Millisecond)
	sink := newSink()
	f := newFeed(t, srv.addr, sink, nil)
	f.SyncOnce(ctx)
	if _, ok := sink.has("block", "192.0.2.0/24"); !ok {
		t.Fatal("entry not installed")
	}
	time.Sleep(1500 * time.Millisecond)
	f.SyncOnce(ctx)
	if _, ok := sink.has("block", "192.0.2.0/24"); ok {
		t.Error("expired key should be gone")
	}
}

func TestInvalidAndTooBroadAreRefused(t *testing.T) {
	srv := startRedis(t)
	rc := srv.client(t)
	ctx := context.Background()
	rc.FlushAll(ctx)
	for _, k := range []string{"t:block:0.0.0.0/0", "t:block:10.0.0.0/4", "t:block:::/0", "t:block:2001::/8",
		"t:block:not-an-ip", "t:block:300.1.1.1"} {
		rc.Set(ctx, k, "x", 0)
	}
	rc.Set(ctx, "t:block:10.0.0.0/8", "ok: exactly the floor", 0)
	rc.Set(ctx, "t:allow:0.0.0.0/0", "allow may be broad", 0)
	sink := newSink()
	f := newFeed(t, srv.addr, sink, nil)
	f.SyncOnce(ctx)
	if n := sink.count("block"); n != 1 {
		t.Errorf("only the /8 should be installed, got %d entries", n)
	}
	if _, ok := sink.has("allow", "0.0.0.0/0"); !ok {
		t.Error("broad allow should be accepted")
	}
	var m metrics.Set
	f.Collect(&m)
	var sb strings.Builder
	m.Write(&sb)
	if !strings.Contains(sb.String(), "bladerunner_redis_invalid_keys_total 6") {
		t.Errorf("expected 6 invalid keys counted:\n%s", sb.String())
	}
}

func TestHostBitsAreMasked(t *testing.T) {
	srv := startRedis(t)
	rc := srv.client(t)
	ctx := context.Background()
	rc.FlushAll(ctx)
	rc.Set(ctx, "t:block:203.0.113.77/24", "x", 0)
	sink := newSink()
	newFeed(t, srv.addr, sink, nil).SyncOnce(ctx)
	if _, ok := sink.has("block", "203.0.113.0/24"); !ok {
		t.Error("203.0.113.77/24 should be stored as 203.0.113.0/24")
	}
}

func TestYAMLEntriesAreNeverDeletedOrShortened(t *testing.T) {
	srv := startRedis(t)
	rc := srv.client(t)
	ctx := context.Background()
	rc.FlushAll(ctx)
	static := func(set string) []netip.Prefix {
		if set == "allow" {
			return []netip.Prefix{netip.MustParsePrefix("192.0.2.10/32")}
		}
		return nil
	}
	sink := newSink()
	sink.PutPrefix("allow", netip.MustParsePrefix("192.0.2.10/32"), 0) // as the engine does from YAML
	// Redis lists the same prefix, with a short TTL.
	rc.Set(ctx, "t:allow:192.0.2.10/32", "dup", 5*time.Second)
	f := newFeed(t, srv.addr, sink, static)
	f.SyncOnce(ctx)
	if d, ok := sink.has("allow", "192.0.2.10/32"); !ok || d != 0 {
		t.Errorf("YAML entry must stay permanent, got ttl=%v present=%v", d, ok)
	}
	rc.Del(ctx, "t:allow:192.0.2.10/32")
	f.SyncOnce(ctx)
	if _, ok := sink.has("allow", "192.0.2.10/32"); !ok {
		t.Error("removing the key from Redis must not delete a YAML entry")
	}
}

func TestMaxEntriesCaps(t *testing.T) {
	srv := startRedis(t)
	rc := srv.client(t)
	ctx := context.Background()
	rc.FlushAll(ctx)
	for i := 0; i < 20; i++ {
		rc.Set(ctx, fmt.Sprintf("t:block:203.0.113.%d", i), "x", 0)
	}
	c := testCfg(srv.addr)
	c.MaxEntries = 5
	sink := newSink()
	f, _ := New(c, sink, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	defer f.Close()
	f.SyncOnce(ctx)
	if n := sink.count("block"); n != 5 {
		t.Errorf("want 5 entries (cap), got %d", n)
	}
}

// The key safety property: when Redis disappears, nothing is removed; when it
// comes back, syncing resumes and picks up changes made meanwhile.
func TestOutageFailsOpenAndRecovers(t *testing.T) {
	srv := startRedis(t)
	if srv.name == "" {
		t.Skip("outage test needs the container started by the test (cannot stop an external Redis)")
	}
	rc := srv.client(t)
	ctx := context.Background()
	rc.FlushAll(ctx)
	rc.Set(ctx, "t:block:203.0.113.0/24", "x", 0)
	rc.Set(ctx, "t:allow:10.1.2.0/24", "x", 0)
	sink := newSink()
	f := newFeed(t, srv.addr, sink, nil)
	if err := f.SyncOnce(ctx); err != nil {
		t.Fatal(err)
	}

	if out, err := exec.Command("docker", "stop", "-t", "0", srv.name).CombinedOutput(); err != nil {
		t.Fatalf("stop: %v %s", err, out)
	}
	start := time.Now()
	for i := 0; i < 3; i++ {
		if err := f.SyncOnce(ctx); err == nil {
			t.Fatal("sync should fail while Redis is down")
		}
	}
	if time.Since(start) > 30*time.Second {
		t.Errorf("outage syncs must not hang, took %v", time.Since(start))
	}
	if _, ok := sink.has("block", "203.0.113.0/24"); !ok {
		t.Error("FAIL-OPEN VIOLATED: block entry removed during outage")
	}
	if _, ok := sink.has("allow", "10.1.2.0/24"); !ok {
		t.Error("FAIL-OPEN VIOLATED: allow entry removed during outage")
	}
	var m metrics.Set
	f.Collect(&m)
	var sb strings.Builder
	m.Write(&sb)
	if !strings.Contains(sb.String(), "bladerunner_redis_up 0") {
		t.Errorf("redis_up should be 0 during an outage:\n%s", sb.String())
	}

	// Redis returns (container restarted; its data is gone, as after a flush).
	if out, err := exec.Command("docker", "start", srv.name).CombinedOutput(); err != nil {
		t.Fatalf("start: %v %s", err, out)
	}
	var err error
	for i := 0; i < 50; i++ {
		if err = f.SyncOnce(ctx); err == nil {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("feed did not recover: %v", err)
	}
	// Redis now authoritatively says the lists are empty, so they are removed.
	if _, ok := sink.has("block", "203.0.113.0/24"); ok {
		t.Error("after recovery the (now empty) Redis state should apply")
	}
}

func TestDownAtStartupDoesNotBreakNew(t *testing.T) {
	sink := newSink()
	f, err := New(testCfg("127.0.0.1:1"), sink, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	if err != nil {
		t.Fatalf("New must not need Redis: %v", err)
	}
	defer f.Close()
	if err := f.SyncOnce(context.Background()); err == nil {
		t.Error("expected an error talking to a closed port")
	}
	if sink.count("block")+sink.count("allow") != 0 {
		t.Error("nothing should be written")
	}
}

func TestParse(t *testing.T) {
	cases := []struct {
		list, in, want string
		ok             bool
	}{
		{"block", "1.2.3.4", "1.2.3.4/32", true},
		{"block", "::ffff:1.2.3.4", "1.2.3.4/32", true},
		{"block", "1.2.3.4/24", "1.2.3.0/24", true},
		{"block", "0.0.0.0/0", "", false},
		{"block", "10.0.0.0/7", "", false},
		{"block", "8000::/15", "", false},
		{"block", "garbage", "", false},
		{"allow", "0.0.0.0/0", "0.0.0.0/0", true},
	}
	for _, c := range cases {
		p, ok := parse(c.list, c.in)
		if ok != c.ok || (ok && p.String() != c.want) {
			t.Errorf("parse(%s,%q) = %v,%v want %v,%v", c.list, c.in, p, ok, c.want, c.ok)
		}
	}
}
