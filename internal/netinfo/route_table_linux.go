//go:build linux

package netinfo

import (
	"bufio"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// ReadRouteTable returns the IPv4 routing table from /proc/net/route.
// Entries with the RTF_UP flag clear are skipped. Deletion is not supported
// on Linux (see DeleteRouteEntry).
func ReadRouteTable() []RouteEntry {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return nil
	}
	defer f.Close()

	var out []RouteEntry
	scanner := bufio.NewScanner(f)
	header := true
	for scanner.Scan() {
		line := scanner.Text()
		if header {
			header = false
			continue // skip column header row
		}
		fields := strings.Fields(line)
		// Columns: Iface Destination Gateway Flags RefCnt Use Metric Mask …
		if len(fields) < 8 {
			continue
		}
		dest, err1 := decodeHexIPLE(fields[1])
		gw, err2 := decodeHexIPLE(fields[2])
		mask, err3 := decodeHexIPLE(fields[7])
		if err1 != nil || err2 != nil || err3 != nil {
			continue
		}
		flags, _ := strconv.ParseUint(fields[3], 16, 32)
		if flags&0x01 == 0 { // RTF_UP clear — route not active
			continue
		}
		metric, _ := strconv.ParseUint(fields[6], 10, 32)
		routeType := "direct"
		if flags&0x02 != 0 { // RTF_GATEWAY
			routeType = "indirect"
		}
		out = append(out, RouteEntry{
			Dest:    dest,
			Mask:    mask,
			Gateway: gw,
			Metric:  uint32(metric),
			Type:    routeType,
		})
	}
	return out
}

// decodeHexIPLE converts an 8-character little-endian hex string (as found in
// /proc/net/route) into a dotted-decimal IPv4 string. E.g. "0101A8C0" → "192.168.1.1".
func decodeHexIPLE(s string) (string, error) {
	if len(s) != 8 {
		return "", fmt.Errorf("unexpected length %d", len(s))
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return "", err
	}
	// /proc/net/route stores addresses in host byte order on LE systems, which
	// means the raw bytes are already in the "network order seen on the wire"
	// when interpreted as little-endian. The byte at index 0 is the least-
	// significant byte of the uint32(i.e. the first octet on the wire).
	return fmt.Sprintf("%d.%d.%d.%d", b[0], b[1], b[2], b[3]), nil
}

// DeleteRouteEntry is not supported on Linux. Use 'ip route del' manually.
func DeleteRouteEntry(_ string) error {
	return errors.New("route deletion is not supported on this platform")
}
