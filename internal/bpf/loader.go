package bpf

import (
	"bytes"
	_ "embed"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

// The compiled BPF object is embedded in the Go binary, so the shipped `bladerunner` is a
// single self-contained file. `make bpf` must run before `go build`; the file is
// not committed (it is a build artifact).
//
//go:embed bladerunner.bpf.o
var objBytes []byte

// Objects holds the loaded program and every map. The `ebpf:"..."` tags are the
// names of the corresponding objects inside the BPF ELF file, which
// spec.LoadAndAssign uses to fill the fields. Prog is nil when Objects was built
// by OpenPinned (the CLI only needs the maps).
type Objects struct {
	Prog       *ebpf.Program `ebpf:"bladerunner_xdp"`
	Cfg        *ebpf.Map     `ebpf:"cfg"`
	Stats      *ebpf.Map     `ebpf:"stats"`
	Allow4     *ebpf.Map     `ebpf:"allow4"`
	Allow6     *ebpf.Map     `ebpf:"allow6"`
	Block4     *ebpf.Map     `ebpf:"block4"`
	Block6     *ebpf.Map     `ebpf:"block6"`
	Protect4   *ebpf.Map     `ebpf:"protect4"`
	Protect6   *ebpf.Map     `ebpf:"protect6"`
	AmpPorts   *ebpf.Map     `ebpf:"amp_ports"`
	FPRules    *ebpf.Map     `ebpf:"fp_rules"`
	FPCounters *ebpf.Map     `ebpf:"fp_counters"`
	FPBuckets  *ebpf.Map     `ebpf:"fp_buckets"`
	RL4        *ebpf.Map     `ebpf:"rl4"`
	RL6        *ebpf.Map     `ebpf:"rl6"`
	Samples    *ebpf.Map     `ebpf:"samples"`
}

// Load loads the embedded object into the kernel. The verifier runs here, so any
// verifier rejection surfaces as an error with the full verifier log.
func Load() (*Objects, error) {
	// Older kernels count BPF memory against RLIMIT_MEMLOCK; lift the cap so loading cannot fail on a low default (no-op on 5.11+).
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock: %w", err)
	}
	// Parse the ELF (maps, programs, BTF) without touching the kernel yet.
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(objBytes))
	if err != nil {
		return nil, fmt.Errorf("parse object: %w", err)
	}
	var o Objects
	// Create the maps, load and verify the program, and assign them to o by tag.
	if err := spec.LoadAndAssign(&o, nil); err != nil {
		// Unwrap verifier errors so the user sees the verifier's own explanation, not just "invalid argument".
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			return nil, fmt.Errorf("verifier: %+v", ve)
		}
		return nil, fmt.Errorf("load: %w", err)
	}
	return &o, nil
}

// maps lists every map by its on-disk (pin) name. Close, Pin and OpenPinned all
// iterate this single table, so adding a map means adding one line here.
func (o *Objects) maps() map[string]**ebpf.Map {
	return map[string]**ebpf.Map{
		"cfg": &o.Cfg, "stats": &o.Stats, "allow4": &o.Allow4, "allow6": &o.Allow6,
		"block4": &o.Block4, "block6": &o.Block6, "protect4": &o.Protect4,
		"protect6": &o.Protect6, "amp_ports": &o.AmpPorts, "fp_rules": &o.FPRules,
		"fp_counters": &o.FPCounters, "fp_buckets": &o.FPBuckets,
		"rl4": &o.RL4, "rl6": &o.RL6, "samples": &o.Samples,
	}
}

// Close releases all kernel objects held by this process. Pinned objects and
// attached pinned links survive: the kernel keeps them alive by reference count.
func (o *Objects) Close() {
	for _, m := range o.maps() {
		if *m != nil {
			(*m).Close()
		}
	}
	if o.Prog != nil {
		o.Prog.Close()
	}
}

// Pin pins every map and the program under dir (which must be on bpffs) so that
// other processes - the `bladerunner` CLI - can open the same live maps by path.
// Pin pins every map (and the program) under dir, which must be on bpffs.
func (o *Objects) Pin(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	for name, m := range o.maps() {
		if err := (*m).Pin(filepath.Join(dir, name)); err != nil {
			return fmt.Errorf("pin %s: %w", name, err)
		}
	}
	return o.Prog.Pin(filepath.Join(dir, "bladerunner_xdp"))
}

// Unpin removes the pins created by Pin, including the link pin. Dropping the
// last reference to a pinned XDP link makes the kernel detach the program.
func Unpin(dir string) error {
	return os.RemoveAll(dir)
}

// OpenPinned opens the maps of a running instance by their pin paths. This is how
// every CLI subcommand talks to the daemon: there is no RPC, just shared maps.
func OpenPinned(dir string) (*Objects, error) {
	o := &Objects{}
	for name, m := range o.maps() {
		pm, err := ebpf.LoadPinnedMap(filepath.Join(dir, name), nil)
		if err != nil {
			o.Close()
			return nil, fmt.Errorf("open %s (is bladerunner running?): %w", name, err)
		}
		*m = pm
	}
	return o, nil
}

// PinLink pins the XDP link itself so the program stays attached after the
// daemon exits (--persist). Without it, closing the link detaches XDP.
func PinLink(l link.Link, dir string) error {
	return l.Pin(filepath.Join(dir, "link"))
}

// Mode selects the XDP attach mode.
type Mode string

const (
	// ModeNative runs in the NIC driver's receive path (fastest). Needs driver support.
	ModeNative Mode = "native" // driver mode: requires NIC driver support
	// ModeGeneric runs after skb allocation, works on any netdev (lab/veth), but is slow.
	ModeGeneric Mode = "generic" // skb mode: works anywhere, slower
)

// Attach attaches the program using a BPF link (not the legacy netlink attach),
// so ownership is tied to the link's file descriptor and it is detached
// automatically if the process dies - unless the link is pinned.
func (o *Objects) Attach(iface string, m Mode) (link.Link, error) {
	ifc, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, err
	}
	var fl link.XDPAttachFlags
	switch m {
	case ModeNative:
		fl = link.XDPDriverMode
	case ModeGeneric:
		fl = link.XDPGenericMode
	default:
		return nil, fmt.Errorf("unknown mode %q", m)
	}
	return link.AttachXDP(link.XDPOptions{Program: o.Prog, Interface: ifc.Index, Flags: fl})
}

// NowNS returns CLOCK_MONOTONIC in ns. It MUST be the same clock as the BPF
// helper bpf_ktime_get_ns, because expiry timestamps written here are compared
// against it in the data plane. (CLOCK_BOOTTIME would be a different clock.)
func NowNS() uint64 {
	var ts unix.Timespec
	_ = unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts)
	return uint64(ts.Sec)*1e9 + uint64(ts.Nsec)
}

// Convert a TTL into an absolute in-kernel expiry timestamp; ttl <= 0 means never.
func expiry(ttl time.Duration) uint64 {
	if ttl <= 0 {
		return 0
	}
	return NowNS() + uint64(ttl)
}

// SetConfig writes the single config entry (key 0). The whole struct is replaced; callers read-modify-write.
func (o *Objects) SetConfig(c Config) error {
	return o.Cfg.Put(uint32(0), c)
}

// GetConfig reads the current config back.
func (o *Objects) GetConfig() (c Config, err error) {
	err = o.Cfg.Lookup(uint32(0), &c)
	return
}

// Select the LPM map for a set name ("allow"|"block"|"protect") and address family.
func prefixMap(o *Objects, set string, v6 bool) *ebpf.Map {
	switch {
	case set == "allow" && !v6:
		return o.Allow4
	case set == "allow":
		return o.Allow6
	case set == "block" && !v6:
		return o.Block4
	case set == "block":
		return o.Block6
	case set == "protect" && !v6:
		return o.Protect4
	}
	return o.Protect6
}

// Build the LPM key for a prefix. The prefix is masked so host bits can never create a duplicate or shadow entry.
func lpmKey(p netip.Prefix) any {
	p = p.Masked()
	if p.Addr().Is4() {
		return lpm4Key{PrefixLen: uint32(p.Bits()), Addr: p.Addr().As4()}
	}
	return lpm6Key{PrefixLen: uint32(p.Bits()), Addr: p.Addr().As16()}
}

// PutPrefix adds a prefix to one of "allow", "block", "protect". ttl <= 0 means
// permanent. Expiry is enforced in-kernel, so a TTL block ends on time even if the
// daemon has died. IPv4-mapped IPv6 addresses are unmapped first so ::ffff:1.2.3.4
// lands in the IPv4 trie where IPv4 packets will actually look.
func (o *Objects) PutPrefix(set string, p netip.Prefix, ttl time.Duration) error {
	if !p.IsValid() {
		return fmt.Errorf("invalid prefix")
	}
	p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits())
	return prefixMap(o, set, p.Addr().Is6()).Put(lpmKey(p), LPMVal{ExpiresNS: expiry(ttl)})
}

// DelPrefix removes a prefix; a missing entry is not an error (deletes are idempotent).
func (o *Objects) DelPrefix(set string, p netip.Prefix) error {
	p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits())
	err := prefixMap(o, set, p.Addr().Is6()).Delete(lpmKey(p))
	if errors.Is(err, ebpf.ErrKeyNotExist) {
		return nil
	}
	return err
}

// PrefixEntry is one listed prefix with its remaining lifetime.
type PrefixEntry struct {
	Prefix  netip.Prefix
	Expires time.Duration // remaining; 0 = permanent
	Expired bool
}

// ListPrefixes enumerates a set (both families) by iterating the trie.
func (o *Objects) ListPrefixes(set string) ([]PrefixEntry, error) {
	var out []PrefixEntry
	now := NowNS()
	for _, v6 := range []bool{false, true} {
		m := prefixMap(o, set, v6)
		var it *ebpf.MapIterator
		var k4 lpm4Key
		var k6 lpm6Key
		var v LPMVal
		if v6 {
			it = m.Iterate()
			for it.Next(&k6, &v) {
				out = append(out, mkEntry(netip.PrefixFrom(netip.AddrFrom16(k6.Addr), int(k6.PrefixLen)), v, now))
			}
		} else {
			it = m.Iterate()
			for it.Next(&k4, &v) {
				out = append(out, mkEntry(netip.PrefixFrom(netip.AddrFrom4(k4.Addr), int(k4.PrefixLen)), v, now))
			}
		}
		if err := it.Err(); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// Convert a raw map value into a PrefixEntry relative to "now".
func mkEntry(p netip.Prefix, v LPMVal, now uint64) PrefixEntry {
	e := PrefixEntry{Prefix: p}
	if v.ExpiresNS != 0 {
		if v.ExpiresNS <= now {
			e.Expired = true
		} else {
			e.Expires = time.Duration(v.ExpiresNS - now)
		}
	}
	return e
}

// SweepExpired deletes entries whose in-kernel TTL has passed. This is pure
// housekeeping to free trie nodes: the data plane already ignores expired entries.
func (o *Objects) SweepExpired(set string) (int, error) {
	es, err := o.ListPrefixes(set)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, e := range es {
		if e.Expired {
			if err := o.DelPrefix(set, e.Prefix); err == nil {
				n++
			}
		}
	}
	return n, nil
}

// SetAmpPorts replaces the amplification table: stale ports are deleted first,
// then the desired ones are written. minLen 0 means drop every packet from the port.
func (o *Objects) SetAmpPorts(ports map[uint16]uint16) error {
	var k uint16
	var v Amp
	var del []uint16
	it := o.AmpPorts.Iterate()
	for it.Next(&k, &v) {
		if _, ok := ports[k]; !ok {
			del = append(del, k)
		}
	}
	for _, d := range del {
		_ = o.AmpPorts.Delete(d)
	}
	for p, ml := range ports {
		if err := o.AmpPorts.Put(p, Amp{MinLen: ml}); err != nil {
			return err
		}
	}
	return it.Err()
}

// SetFPRules installs the fingerprint rule set and updates the scan length.
// Ordering matters for safety: all 32 slots are written (unused ones zeroed,
// action NONE) BEFORE fp_n is published, so the data plane never scans a
// half-written table. cfgMut lets a caller tweak other config fields in the same
// read-modify-write.
func (o *Objects) SetFPRules(rules []FPRule, cfgMut func(*Config)) error {
	if len(rules) > MaxFPRules {
		return fmt.Errorf("%d rules exceeds max %d", len(rules), MaxFPRules)
	}
	for i := 0; i < MaxFPRules; i++ {
		var r FPRule
		if i < len(rules) {
			r = rules[i]
		}
		if err := o.FPRules.Put(uint32(i), r); err != nil {
			return err
		}
	}
	c, err := o.GetConfig()
	if err != nil {
		return err
	}
	c.FPN = uint32(len(rules))
	if cfgMut != nil {
		cfgMut(&c)
	}
	return o.SetConfig(c)
}

// ReadStats sums the per-CPU counters into one total per slot. A PERCPU_ARRAY
// lookup returns one value per possible CPU, hence the slice.
func (o *Objects) ReadStats() ([NStat]Counter, error) {
	var out [NStat]Counter
	for i := 0; i < NStat; i++ {
		var per []Counter
		if err := o.Stats.Lookup(uint32(i), &per); err != nil {
			return out, err
		}
		for _, c := range per {
			out[i].Pkts += c.Pkts
			out[i].Bytes += c.Bytes
		}
	}
	return out, nil
}

// ReadFPCounters sums the per-CPU rule counters for the first n rule slots.
func (o *Objects) ReadFPCounters(n int) ([]FPCounter, error) {
	out := make([]FPCounter, n)
	for i := 0; i < n; i++ {
		var per []FPCounter
		if err := o.FPCounters.Lookup(uint32(i), &per); err != nil {
			return nil, err
		}
		for _, c := range per {
			out[i].MatchedPkts += c.MatchedPkts
			out[i].MatchedBytes += c.MatchedBytes
			out[i].DroppedPkts += c.DroppedPkts
			out[i].DroppedBytes += c.DroppedBytes
		}
	}
	return out, nil
}
