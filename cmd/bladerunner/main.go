// Command bladerunner is the bladerunner daemon and its control CLI.
//
// Architecture note: there is NO RPC between `bladerunner run` and the other subcommands.
// The daemon pins its BPF maps under a bpffs directory; every other subcommand
// opens those same live maps by path. That keeps the CLI trivially robust (it works
// even if the daemon is wedged) and means CLI changes take effect on the very next
// packet.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"golang.org/x/sys/unix"

	"github.com/ishworgurung/bladerunner/internal/bpf"
	"github.com/ishworgurung/bladerunner/internal/config"
	"github.com/ishworgurung/bladerunner/internal/engine"
	"github.com/ishworgurung/bladerunner/internal/feed"
	"github.com/ishworgurung/bladerunner/internal/metrics"
)

// version is stamped at build time via -ldflags "-X main.version=...".
var version = "dev"

// Default bpffs location for the pinned maps. Must live under /sys/fs/bpf.
const defaultPin = "/sys/fs/bpf/bladerunner"

// usage is the text printed by `bladerunner help` and on bad invocations.
const usage = `bladerunner - XDP DDoS mitigation

usage: bladerunner <command> [flags]

  run [-c file] [--iface IF] [--mode native|generic] [--dry-run=BOOL] [--persist]
      [--last-good FILE] [--wait-iface DUR]
                     load, attach and manage the data plane (needs root)
  systemd [--install] [--config FILE] [--bin PATH]
                     print (or install) a systemd unit that starts the filter before
                     the network comes up, with last-known-good config fallback
  status             attack state, flags and verdict counters
  stats              per-reason packet/byte counters
  block   PREFIX [--ttl DUR]     drop a source prefix (optionally temporary)
  unblock PREFIX
  allow   PREFIX     never filter a source prefix
  unallow PREFIX
  protect PREFIX     destinations to defend (with protected-only mode)
  unprotect PREFIX
  list block|allow|protect
  rules              active fingerprint rules and their counters
  dryrun on|off      toggle dry-run live
  detach             remove pins/link left by a --persist run
  version

common flag: --pin DIR (default ` + defaultPin + `)
`

// main dispatches on the first argument. Each subcommand parses its own flags with
// the standard flag package (no third-party CLI dependency); errors are printed
// once with a "bladerunner:" prefix and the process exits non-zero.
func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	var err error
	switch cmd {
	case "run":
		err = cmdRun(args)
	case "status":
		err = withObjs(args, cmdStatus)
	case "stats":
		err = withObjs(args, cmdStats)
	case "block", "unblock", "allow", "unallow", "protect", "unprotect":
		err = cmdPrefix(cmd, args)
	case "list":
		err = cmdList(args)
	case "rules":
		err = withObjs(args, cmdRules)
	case "dryrun":
		err = cmdDryRun(args)
	case "detach":
		err = cmdDetach(args)
	case "systemd":
		err = cmdSystemd(args)
	case "version", "--version", "-v":
		fmt.Println("bladerunner", version)
	case "help", "-h", "--help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", cmd, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "bladerunner:", err)
		os.Exit(1)
	}
}

// ensureBPFFS mounts bpffs at /sys/fs/bpf if nothing is mounted there. Pinning
// requires bpffs; most distros mount it at boot, but minimal containers do not.
func ensureBPFFS(dir string) error {
	root := "/sys/fs/bpf"
	if !strings.HasPrefix(dir, root) {
		return nil
	}
	var fs unix.Statfs_t
	if err := unix.Statfs(root, &fs); err == nil && fs.Type == unix.BPF_FS_MAGIC {
		return nil
	}
	if err := unix.Mount("bpf", root, "bpf", 0, ""); err != nil {
		return fmt.Errorf("mount bpffs on %s: %w", root, err)
	}
	return nil
}

// cmdRun is the daemon: load -> configure -> pin -> attach -> run until signalled.
// ORDER IS DELIBERATE: maps are populated (and pinned) BEFORE the program is
// attached, so the very first packet the filter sees already has the allowlist,
// limits and amp table in place.
func cmdRun(args []string) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	cfgPath := fs.String("c", "", "config file (YAML)")
	iface := fs.String("iface", "", "interface (overrides config)")
	mode := fs.String("mode", "", "native|generic (overrides config)")
	dry := fs.String("dry-run", "", "true|false (overrides config)")
	// Command-line flags override the YAML file; the result is re-validated below.
	persist := fs.Bool("persist", false, "keep XDP attached if the daemon exits")
	lastGood := fs.String("last-good", "", "file holding the last known-good config: used if -c fails to load, and updated after a good start")
	waitIface := fs.Duration("wait-iface", 0, "wait up to this long for the interface to appear (early boot)")
	fs.Parse(args)

	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	cfg, usedLastGood, err := config.LoadWithFallback(*cfgPath, *lastGood)
	if err != nil {
		return err
	}
	if usedLastGood {
		log.Error("config rejected: running with the LAST KNOWN-GOOD copy instead; fix the config file",
			"config", *cfgPath, "last_good", *lastGood)
	}
	if *iface != "" {
		cfg.Interface = *iface
	}
	if *mode != "" {
		cfg.Mode = *mode
	}
	switch *dry {
	case "true":
		cfg.DryRun = true
	case "false":
		cfg.DryRun = false
	case "":
	default:
		return fmt.Errorf("--dry-run must be true or false")
	}
	if *persist {
		cfg.Persist = true
	}
	if cfg.Interface == "" {
		return errors.New("no interface: set `interface:` in the config or pass --iface")
	}
	if err := cfg.Validate(); err != nil {
		return err
	}

	if *waitIface > 0 {
		if err := waitForInterface(cfg.Interface, *waitIface); err != nil {
			return err
		}
	}
	// A leftover pin directory means another instance (or a --persist run) is active.
	// Refusing is safer than silently replacing a live filter.
	if _, err := os.Stat(cfg.PinDir); err == nil {
		return fmt.Errorf("%s exists: another instance (or a --persist run) is active; run `bladerunner detach` first", cfg.PinDir)
	}
	if err := ensureBPFFS(cfg.PinDir); err != nil {
		return err
	}

	o, err := bpf.Load()
	if err != nil {
		return err
	}
	defer o.Close()

	// Populate maps from the config before anything can observe the program.
	eng := engine.New(cfg, o, log)
	if err := eng.Apply(); err != nil {
		return err
	}
	// Pin so the CLI can reach this instance. On failure, clean up partial pins.
	if err := o.Pin(cfg.PinDir); err != nil {
		bpf.Unpin(cfg.PinDir)
		return err
	}
	// Without --persist the pins are removed on exit; with it they are left for `bladerunner detach`.
	cleanup := func() {
		if !cfg.Persist {
			bpf.Unpin(cfg.PinDir)
		}
	}
	defer cleanup()

	// The program is attached only after maps are populated and pinned.
	// Attach LAST. From this instruction on, packets are being filtered.
	l, err := o.Attach(cfg.Interface, bpf.Mode(cfg.Mode))
	if err != nil {
		return fmt.Errorf("attach %s (%s mode): %w", cfg.Interface, cfg.Mode, err)
	}
	// Pin the link so the kernel keeps XDP attached even after this process exits.
	if cfg.Persist {
		if err := bpf.PinLink(l, cfg.PinDir); err != nil {
			l.Close()
			return fmt.Errorf("pin link: %w", err)
		}
	}
	// Closing an unpinned link detaches XDP; a pinned one survives. So defer is correct in both modes.
	defer l.Close() // detaches unless the link is pinned
	log.Info("attached", "iface", cfg.Interface, "mode", cfg.Mode, "dry_run", cfg.DryRun,
		"persist", cfg.Persist, "pin", cfg.PinDir, "version", version)
	// Shout about dry-run at startup: the most common mistake is forgetting it is on.
	if cfg.DryRun {
		log.Warn("DRY-RUN: traffic is classified and counted but NOT dropped; restart with --dry-run=false to enforce")
	}

	// SIGINT/SIGTERM cancel ctx, which stops the engine and runs the deferred cleanup.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// The config has loaded, validated and attached: remember it as the last known-good
	// copy (but never overwrite it with a fallback we are merely running from).
	if *lastGood != "" && !usedLastGood {
		if err := config.SaveLastGood(*cfgPath, *lastGood); err != nil {
			log.Warn("could not save the last known-good config", "path", *lastGood, "err", err)
		}
	}
	// Tell systemd (Type=notify) that the filter is now in place.
	sdNotify("READY=1\nSTATUS=filtering on " + cfg.Interface)
	defer sdNotify("STOPPING=1")

	// Optional Redis feed of shared allow/block lists. The connection is lazy, so an
	// unreachable Redis never stops the daemon from starting (fail-open).
	var rfeed *feed.Feed
	if cfg.Redis.Enabled {
		rfeed, err = feed.New(cfg.Redis, o, log, eng.StaticPrefixes)
		if err != nil {
			return err
		}
		defer rfeed.Close()
		go rfeed.Run(ctx)
		log.Info("redis feed enabled", "addr", cfg.Redis.Addr, "prefix", cfg.Redis.KeyPrefix, "poll", cfg.Redis.PollInterval)
	}

	// Optional Prometheus endpoint, bound to localhost by default.
	if cfg.Metrics != "" {
		mux := http.NewServeMux()
		mux.Handle("/metrics", metricsHandler(eng, rfeed))
		srv := &http.Server{Addr: cfg.Metrics, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
		go func() {
			if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Error("metrics server", "err", err)
			}
		}()
		defer srv.Close()
		log.Info("metrics", "addr", cfg.Metrics)
	}

	// SIGHUP: re-read the YAML and re-apply it live without detaching.
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	go func() {
		for range hup {
			nc, err := config.Load(*cfgPath)
			if err != nil {
				log.Error("reload rejected", "err", err)
				continue
			}
			// Interface, mode, persist, pin dir and the redis connection cannot change live.
			nc.Interface, nc.Mode, nc.Persist, nc.PinDir, nc.Redis = cfg.Interface, cfg.Mode, cfg.Persist, cfg.PinDir, cfg.Redis
			if err := eng.Reload(nc); err != nil {
				log.Error("reload failed", "err", err)
				continue
			}
			if err := config.SaveLastGood(*cfgPath, *lastGood); err != nil {
				log.Warn("could not save the last known-good config", "path", *lastGood, "err", err)
			}
			log.Info("config reloaded (prefixes are added, never removed; use `bladerunner unblock`)")
		}
	}()

	// Blocks until shutdown.
	err = eng.Run(ctx)
	if cfg.Persist {
		log.Warn("exiting; XDP program stays attached (persist). Remove with `bladerunner detach`")
	} else {
		log.Info("detaching")
	}
	return err
}

// Shared helpers and the remaining subcommands.
// ------------------------------------------------------------- CLI helpers

// pinFlag registers the --pin flag shared by every CLI subcommand.
func pinFlag(fs *flag.FlagSet) *string {
	return fs.String("pin", defaultPin, "bpffs pin directory")
}

// withObjs opens the pinned maps of a running instance, runs fn, and closes them.
func withObjs(args []string, fn func(*bpf.Objects) error) error {
	fs := flag.NewFlagSet("bladerunner", flag.ExitOnError)
	pin := pinFlag(fs)
	fs.Parse(args)
	o, err := bpf.OpenPinned(*pin)
	if err != nil {
		return err
	}
	defer o.Close()
	return fn(o)
}

// human formats big counters compactly (1.23M, 4.5G).
func human(n uint64) string {
	f := float64(n)
	for _, u := range []string{"", "K", "M", "G", "T"} {
		if f < 1000 {
			if u == "" {
				return fmt.Sprintf("%d", n)
			}
			return fmt.Sprintf("%.2f%s", f, u)
		}
		f /= 1000
	}
	return fmt.Sprintf("%.2fP", f)
}

// cmdStats prints one row per verdict reason plus the sampling counters.
func cmdStats(o *bpf.Objects) error {
	st, err := o.ReadStats()
	if err != nil {
		return err
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 8, 2, ' ', 0)
	fmt.Fprintln(tw, "REASON\tVERDICT\tPACKETS\tBYTES")
	for i := 0; i < bpf.NReason; i++ {
		v := "pass"
		if bpf.IsDrop(i) {
			v = "drop"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", bpf.ReasonNames[i], v, human(st[i].Pkts), human(st[i].Bytes))
	}
	fmt.Fprintf(tw, "samples\t-\t%s\t-\n", human(st[bpf.SSampled].Pkts))
	fmt.Fprintf(tw, "samples_lost\t-\t%s\t-\n", human(st[bpf.SSampleLost].Pkts))
	return tw.Flush()
}

// cmdStatus prints the attack state and the active flags, then the counters.
func cmdStatus(o *bpf.Objects) error {
	c, err := o.GetConfig()
	if err != nil {
		return err
	}
	on := func(f uint32) string {
		if c.Flags&f != 0 {
			return "on"
		}
		return "off"
	}
	state := "normal"
	if c.Attack == 1 {
		state = "ATTACK (tightened limits)"
	}
	fmt.Printf("state          %s\n", state)
	fmt.Printf("dry-run        %s\n", on(bpf.FDryRun))
	fmt.Printf("protected-only %s\n", on(bpf.FProtectedOnly))
	fmt.Printf("rate-limit     %s\n", on(bpf.FRateLimit))
	fmt.Printf("amp ports      %s\n", on(bpf.FAmp))
	fmt.Printf("drop frags     %s\n", on(bpf.FDropFrags))
	fmt.Printf("sanity         %s\n", on(bpf.FSanity))
	fmt.Printf("sample rate    1/%d\n", c.SampleRate)
	fmt.Printf("fp rules       %d\n\n", c.FPN)
	return cmdStats(o)
}

// cmdRules lists the active fingerprint rules read straight from the kernel table
// (not from daemon memory), with remaining lifetime and match/drop counters.
func cmdRules(o *bpf.Objects) error {
	c, err := o.GetConfig()
	if err != nil {
		return err
	}
	cs, err := o.ReadFPCounters(int(c.FPN))
	if err != nil {
		return err
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 8, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tACTION\tFAM\tPROTO\tSPORT\tDPORT\tLEN\tTTL\tFLAGS\tRATE\tTTL-LEFT\tMATCHED\tDROPPED")
	now := bpf.NowNS()
	for i := 0; i < int(c.FPN); i++ {
		var r bpf.FPRule
		if err := o.FPRules.Lookup(uint32(i), &r); err != nil {
			return err
		}
		rng := func(lo, hi uint16) string {
			if lo == 0 && hi == 65535 {
				return "*"
			}
			if lo == hi {
				return fmt.Sprint(lo)
			}
			return fmt.Sprintf("%d-%d", lo, hi)
		}
		act, rate := "drop", "-"
		if r.Action == bpf.FPRateLimit {
			act, rate = "ratelimit", fmt.Sprintf("%dpps", r.RatePPS)
		}
		left := "never"
		if r.ExpiresNS != 0 {
			if r.ExpiresNS <= now {
				left = "expired"
			} else {
				left = (time.Duration(r.ExpiresNS - now)).Round(time.Second).String()
			}
		}
		flags := "-"
		if r.TCPFlagsMask != 0 {
			flags = fmt.Sprintf("%#02x", r.TCPFlagsVal)
		}
		fmt.Fprintf(tw, "%d\t%s\t%d\t%d\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", i, act, r.Family, r.Proto,
			rng(r.SportLo, r.SportHi), rng(r.DportLo, r.DportHi), rng(r.LenLo, r.LenHi),
			rng(uint16(r.TTLLo), uint16(r.TTLHi)), flags, rate, left,
			human(cs[i].MatchedPkts), human(cs[i].DroppedPkts))
	}
	return tw.Flush()
}

// parsePrefix accepts a CIDR or a bare address; a bare address means a single host (/32 or /128).
func parsePrefix(s string) (netip.Prefix, error) {
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("bad prefix %q", s)
	}
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// cmdPrefix implements block/unblock/allow/unallow/protect/unprotect.
// The command name encodes the action: a leading "un" means delete from the set
// named by the rest. Flags may appear before or after the positional prefix.
func cmdPrefix(cmd string, args []string) error {
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	pin := pinFlag(fs)
	ttl := fs.Duration("ttl", 0, "expire after this long (block only; 0 = permanent)")
	// allow flags after the positional prefix too
	var pos []string
	for len(args) > 0 {
		fs.Parse(args)
		if fs.NArg() == 0 {
			break
		}
		pos = append(pos, fs.Arg(0))
		args = fs.Args()[1:]
	}
	if len(pos) != 1 {
		return fmt.Errorf("usage: bladerunner %s PREFIX", cmd)
	}
	p, err := parsePrefix(pos[0])
	if err != nil {
		return err
	}
	o, err := bpf.OpenPinned(*pin)
	if err != nil {
		return err
	}
	defer o.Close()
	set := strings.TrimPrefix(cmd, "un")
	if strings.HasPrefix(cmd, "un") {
		return o.DelPrefix(set, p)
	}
	if *ttl > 0 && set != "block" {
		return errors.New("--ttl applies to block only")
	}
	return o.PutPrefix(set, p, *ttl)
}

// cmdList prints the contents of one prefix set with remaining TTLs.
func cmdList(args []string) error {
	fs := flag.NewFlagSet("list", flag.ExitOnError)
	pin := pinFlag(fs)
	var pos []string
	for len(args) > 0 {
		fs.Parse(args)
		if fs.NArg() == 0 {
			break
		}
		pos = append(pos, fs.Arg(0))
		args = fs.Args()[1:]
	}
	if len(pos) != 1 || (pos[0] != "block" && pos[0] != "allow" && pos[0] != "protect") {
		return errors.New("usage: bladerunner list block|allow|protect")
	}
	o, err := bpf.OpenPinned(*pin)
	if err != nil {
		return err
	}
	defer o.Close()
	es, err := o.ListPrefixes(pos[0])
	if err != nil {
		return err
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 8, 2, ' ', 0)
	fmt.Fprintln(tw, "PREFIX\tEXPIRES")
	for _, e := range es {
		x := "never"
		switch {
		case e.Expired:
			x = "expired"
		case e.Expires > 0:
			x = e.Expires.Round(time.Second).String()
		}
		fmt.Fprintf(tw, "%s\t%s\n", e.Prefix, x)
	}
	return tw.Flush()
}

// cmdDryRun flips the dry-run flag live with a read-modify-write of the config
// entry. Takes effect on the next packet; no reload or restart.
func cmdDryRun(args []string) error {
	fs := flag.NewFlagSet("dryrun", flag.ExitOnError)
	pin := pinFlag(fs)
	var pos []string
	for len(args) > 0 {
		fs.Parse(args)
		if fs.NArg() == 0 {
			break
		}
		pos = append(pos, fs.Arg(0))
		args = fs.Args()[1:]
	}
	if len(pos) != 1 || (pos[0] != "on" && pos[0] != "off") {
		return errors.New("usage: bladerunner dryrun on|off")
	}
	o, err := bpf.OpenPinned(*pin)
	if err != nil {
		return err
	}
	defer o.Close()
	c, err := o.GetConfig()
	if err != nil {
		return err
	}
	if pos[0] == "on" {
		c.Flags |= bpf.FDryRun
	} else {
		c.Flags &^= bpf.FDryRun
	}
	return o.SetConfig(c)
}

// cmdDetach removes the pins. Dropping the last reference to the pinned link makes
// the kernel detach the XDP program, which is how a --persist run is stopped.
func cmdDetach(args []string) error {
	fs := flag.NewFlagSet("detach", flag.ExitOnError)
	pin := pinFlag(fs)
	fs.Parse(args)
	if _, err := os.Stat(filepath.Join(*pin, "link")); err != nil {
		if _, err2 := os.Stat(*pin); err2 != nil {
			return fmt.Errorf("nothing to detach: %s does not exist", *pin)
		}
	}
	// Removing the link pin drops the last reference: the kernel detaches XDP.
	if err := bpf.Unpin(*pin); err != nil {
		return err
	}
	fmt.Println("detached and unpinned", *pin)
	return nil
}

// metricsHandler exposes the engine's collector over HTTP.
func metricsHandler(e *engine.Engine, f *feed.Feed) http.Handler {
	return metricsHTTP(func() *metrics.Set {
		m := e.Collect()
		if f != nil {
			f.Collect(m)
		}
		return m
	})
}
