package main

import (
	"fmt"
	"net"
	"os"
	"time"
)

// sdNotify tells systemd about the service state (sd_notify protocol: a datagram
// to the unix socket named by $NOTIFY_SOCKET). It does nothing outside systemd.
// Used so that a Type=notify unit is "started" only once the filter is attached,
// which is what lets other units be ordered after a working filter.
func sdNotify(state string) {
	addr := os.Getenv("NOTIFY_SOCKET")
	if addr == "" {
		return
	}
	if addr[0] == '@' { // abstract socket
		addr = "\x00" + addr[1:]
	}
	conn, err := net.Dial("unixgram", addr)
	if err != nil {
		return
	}
	defer conn.Close()
	conn.Write([]byte(state))
}

// waitForInterface waits up to d for a network interface to exist. At early boot
// the unit can start before the NIC driver has created the device.
func waitForInterface(name string, d time.Duration) error {
	deadline := time.Now().Add(d)
	for {
		if _, err := net.InterfaceByName(name); err == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("interface %q did not appear within %s", name, d)
		}
		time.Sleep(250 * time.Millisecond)
	}
}
