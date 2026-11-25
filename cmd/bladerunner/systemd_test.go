package main

import (
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func defaultUnit(t *testing.T) string {
	t.Helper()
	out, err := renderUnit(unitData{Bin: "/usr/local/bin/bladerunner", Config: "/etc/bladerunner/bladerunner.yaml",
		Pin: defaultPin, StateDir: "/var/lib/bladerunner", WaitIface: "30s"})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// The directives that make the unit do its job must all be present.
func TestUnitHasTheImportantDirectives(t *testing.T) {
	u := defaultUnit(t)
	for _, want := range []string{
		"DefaultDependencies=no",    // so it can run before the network
		"Before=network-pre.target", // attached before networking starts
		"Wants=network-pre.target",  // and pulls that target in
		"Type=notify",               // "started" means "XDP attached"
		"--last-good /var/lib/bladerunner/last-good.yaml",
		"ConditionPathExists=/etc/bladerunner/bladerunner.yaml",
		"StateDirectory=bladerunner",
		"WantedBy=multi-user.target",
	} {
		if !strings.Contains(u, want) {
			t.Errorf("unit is missing %q", want)
		}
	}
}

func TestUnitRefusesUnsafeValues(t *testing.T) {
	for name, d := range map[string]unitData{
		"relative bin":  {Bin: "bladerunner", Config: "/a", Pin: "/b", StateDir: "/var/lib/x"},
		"space":         {Bin: "/usr/local/bin/my br", Config: "/a", Pin: "/b", StateDir: "/var/lib/x"},
		"percent":       {Bin: "/bin/b", Config: "/a%h", Pin: "/b", StateDir: "/var/lib/x"},
		"newline":       {Bin: "/bin/b", Config: "/a\nExecStart=/bin/evil", Pin: "/b", StateDir: "/var/lib/x"},
		"quote in path": {Bin: "/bin/b", Config: "/a", Pin: "/b\"", StateDir: "/var/lib/x"},
	} {
		if _, err := renderUnit(d); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

// If systemd-analyze is installed, let systemd itself check the unit for mistakes.
func TestUnitPassesSystemdAnalyzeVerify(t *testing.T) {
	sa, err := exec.LookPath("systemd-analyze")
	if err != nil {
		t.Skip("systemd-analyze not installed")
	}
	dir := t.TempDir()
	// verify checks that the executables exist, so point at one that does.
	u, err := renderUnit(unitData{Bin: "/bin/true", Config: "/etc/hostname", Pin: defaultPin,
		StateDir: "/var/lib/bladerunner", WaitIface: "30s"})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "bladerunner.service")
	if err := os.WriteFile(path, []byte(u), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(sa, "verify", path).CombinedOutput()
	if err != nil {
		t.Fatalf("systemd-analyze verify: %v\n%s", err, out)
	}
	// verify exits 0 even for some problems, so also look for complaints about this unit.
	for _, l := range strings.Split(string(out), "\n") {
		if strings.Contains(l, "bladerunner.service") && !strings.Contains(l, "Failed to prepare") {
			t.Errorf("systemd-analyze complained: %s", l)
		}
	}
}

func TestSdNotifyReachesTheSocket(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "notify")
	l, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: sock, Net: "unixgram"})
	if err != nil {
		t.Skip("cannot create a unix datagram socket here:", err)
	}
	defer l.Close()
	t.Setenv("NOTIFY_SOCKET", sock)
	sdNotify("READY=1")
	buf := make([]byte, 64)
	l.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := l.ReadFromUnix(buf)
	if err != nil || string(buf[:n]) != "READY=1" {
		t.Fatalf("got %q, %v", buf[:n], err)
	}
}

func TestSdNotifyIsSilentOutsideSystemd(t *testing.T) {
	t.Setenv("NOTIFY_SOCKET", "")
	sdNotify("READY=1") // must not panic or block
}

func TestWaitForInterface(t *testing.T) {
	if err := waitForInterface("lo", time.Second); err != nil {
		t.Errorf("lo should exist: %v", err)
	}
	if err := waitForInterface("definitely-not-a-nic0", 300*time.Millisecond); err == nil {
		t.Error("expected a timeout for a missing interface")
	}
}
