//go:build linux

package scan

import (
	"bufio"
	"os"
	"strconv"
	"strings"
)

// enrichInterfaceEntries populates Linux-specific fields for each entry by
// reading /sys/class/net/<name>/ (speed, duplex, operstate) and
// /proc/net/dev (traffic counters).
func enrichInterfaceEntries(entries []InterfaceEntry) {
	// Parse /proc/net/dev once and build a name→stats map.
	devStats := readProcNetDev()

	for i := range entries {
		name := entries[i].Name
		base := "/sys/class/net/" + name

		// Link speed in Mbps (kernel reports as a signed integer; -1 means unknown).
		if b, err := os.ReadFile(base + "/speed"); err == nil {
			if v, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64); err == nil && v > 0 {
				entries[i].Speed = v
			}
		}

		// Duplex: "full", "half", or absent on virtual/loopback interfaces.
		if b, err := os.ReadFile(base + "/duplex"); err == nil {
			entries[i].Duplex = strings.TrimSpace(string(b))
		}

		// OperState: more granular than the simple up/down flag.
		// Values: up, down, dormant, lowerlayerdown, testing, unknown, notpresent.
		if b, err := os.ReadFile(base + "/operstate"); err == nil {
			entries[i].OperState = strings.TrimSpace(string(b))
		}

		// Traffic counters.
		if s, ok := devStats[name]; ok {
			entries[i].RXBytes   = s[0]
			entries[i].RXPackets = s[1]
			entries[i].RXErrors  = s[2]
			entries[i].RXDropped = s[3]
			entries[i].TXBytes   = s[4]
			entries[i].TXPackets = s[5]
			entries[i].TXErrors  = s[6]
			entries[i].TXDropped = s[7]
		}
	}
}

// readProcNetDev parses /proc/net/dev and returns a map of interface name →
// [RXBytes, RXPackets, RXErrors, RXDropped, TXBytes, TXPackets, TXErrors, TXDropped].
//
// Column layout (after splitting on ":"):
//
//	Receive:  bytes(0) packets(1) errs(2) drop(3) fifo(4) frame(5) compressed(6) multicast(7)
//	Transmit: bytes(8) packets(9) errs(10) drop(11) fifo(12) colls(13) carrier(14) compressed(15)
func readProcNetDev() map[string][8]uint64 {
	f, err := os.Open("/proc/net/dev")
	if err != nil {
		return nil
	}
	defer f.Close()

	out := make(map[string][8]uint64)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		colon := strings.Index(line, ":")
		if colon < 0 {
			continue
		}
		name := strings.TrimSpace(line[:colon])
		fields := strings.Fields(line[colon+1:])
		if len(fields) < 16 {
			continue
		}
		p := func(s string) uint64 {
			v, _ := strconv.ParseUint(s, 10, 64)
			return v
		}
		out[name] = [8]uint64{
			p(fields[0]),  // RXBytes
			p(fields[1]),  // RXPackets
			p(fields[2]),  // RXErrors
			p(fields[3]),  // RXDropped
			p(fields[8]),  // TXBytes
			p(fields[9]),  // TXPackets
			p(fields[10]), // TXErrors
			p(fields[11]), // TXDropped
		}
	}
	return out
}
