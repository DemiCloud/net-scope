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
	// /proc/net/route stores addresses as little-endian 32-bit integers.
	// hex.DecodeString produces: b[0]=LSB … b[3]=MSB.
	// Network (wire) order is big-endian, so the first octet on the wire is
	// the MSB: b[3].b[2].b[1].b[0].
	// Example: 192.168.1.1 = 0xC0A80101 LE → bytes [0x01,0x01,0xA8,0xC0]
	//          → printed as b[3].b[2].b[1].b[0] = "192.168.1.1".
	return fmt.Sprintf("%d.%d.%d.%d", b[3], b[2], b[1], b[0]), nil
}

// DeleteRouteEntry is not supported on Linux. Use 'ip route del' manually.
func DeleteRouteEntry(_ string) error {
	return errors.New("route deletion is not supported on this platform")
}
