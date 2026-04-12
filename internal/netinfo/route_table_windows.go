//go:build windows

package netinfo

import (
	"fmt"
	"net"
	"strings"
	"syscall"
	"unsafe"
)

var (
	procGetIpForwardTable    = iphlpapi.NewProc("GetIpForwardTable")
	procDeleteIpForwardEntry = iphlpapi.NewProc("DeleteIpForwardEntry")
)

// mibIPForwardRow mirrors MIB_IPFORWARDROW (14 DWORDs = 56 bytes).
type mibIPForwardRow struct {
	dwForwardDest      uint32
	dwForwardMask      uint32
	dwForwardPolicy    uint32
	dwForwardNextHop   uint32
	dwForwardIfIndex   uint32
	dwForwardType      uint32 // 1=other 2=invalid 3=direct 4=indirect
	dwForwardProto     uint32
	dwForwardAge       uint32
	dwForwardNextHopAS uint32
	dwForwardMetric1   uint32
	dwForwardMetric2   uint32
	dwForwardMetric3   uint32
	dwForwardMetric4   uint32
	dwForwardMetric5   uint32
}

var routeProtoNames = map[uint32]string{
	2:     "local",
	3:     "netmgmt",
	4:     "icmp",
	5:     "egp",
	6:     "ggp",
	7:     "hello",
	8:     "rip",
	9:     "is-is",
	10:    "es-is",
	11:    "cisco",
	12:    "bbn",
	13:    "ospf",
	14:    "bgp",
	10002: "static",
	10003: "static-nondod",
}

func routeProtoName(p uint32) string {
	if s, ok := routeProtoNames[p]; ok {
		return s
	}
	return fmt.Sprintf("proto%d", p)
}

func ip4FromLE(v uint32) net.IP {
	return net.IP{byte(v), byte(v >> 8), byte(v >> 16), byte(v >> 24)}
}

func ip4ToLE(ip net.IP) uint32 {
	ip4 := ip.To4()
	if ip4 == nil {
		return 0
	}
	return uint32(ip4[0]) | uint32(ip4[1])<<8 | uint32(ip4[2])<<16 | uint32(ip4[3])<<24
}

// fetchForwardTable calls GetIpForwardTable (size-query then data-query) and
// returns the raw buffer on success, or nil on error. It retries up to 3 times
// if the table grows between the two calls (TOCTOU ERROR_INSUFFICIENT_BUFFER).
// sort=true requests the API to sort entries by destination.
func fetchForwardTable(sort bool) []byte {
	var size uint32
	r, _, _ := procGetIpForwardTable.Call(0, uintptr(unsafe.Pointer(&size)), 0)
	const errInsufficientBuffer = 122
	if r != 0 && r != errInsufficientBuffer {
		return nil
	}
	if size == 0 {
		return nil
	}
	bOrder := uintptr(0)
	if sort {
		bOrder = 1
	}
	for range 3 {
		buf := make([]byte, size)
		r, _, _ = procGetIpForwardTable.Call(
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(unsafe.Pointer(&size)),
			bOrder,
		)
		if r == 0 {
			return buf
		}
		if r != errInsufficientBuffer {
			return nil
		}
		// size was updated by the failed call; retry.
	}
	return nil
}

// forForwardRows calls fn for each MIB_IPFORWARDROW in buf.
// If fn returns false, iteration stops.
func forForwardRows(buf []byte, fn func(*mibIPForwardRow) bool) {
	if len(buf) < 4 {
		return
	}
	numEntries := *(*uint32)(unsafe.Pointer(&buf[0]))
	rowSize := unsafe.Sizeof(mibIPForwardRow{})
	for i := uint32(0); i < numEntries; i++ {
		off := uintptr(4) + uintptr(i)*rowSize
		if off+rowSize > uintptr(len(buf)) {
			break
		}
		if !fn((*mibIPForwardRow)(unsafe.Pointer(&buf[off]))) {
			return
		}
	}
}

// ReadRouteTable returns all IPv4 forwarding-table entries from Windows,
// sorted by destination. Entries with type=invalid (2) are excluded.
func ReadRouteTable() []RouteEntry {
	buf := fetchForwardTable(true)
	if buf == nil {
		return nil
	}
	var out []RouteEntry
	forForwardRows(buf, func(row *mibIPForwardRow) bool {
		if row.dwForwardType == 2 { // invalid
			return true
		}
		dest := ip4FromLE(row.dwForwardDest)
		mask := ip4FromLE(row.dwForwardMask)
		gw := ip4FromLE(row.dwForwardNextHop)
		routeType := "indirect"
		if row.dwForwardType == 3 {
			routeType = "direct"
		}
		out = append(out, RouteEntry{
			Dest:     dest.String(),
			Mask:     mask.String(),
			Gateway:  gw.String(),
			IfIndex:  row.dwForwardIfIndex,
			Metric:   row.dwForwardMetric1,
			Protocol: routeProtoName(row.dwForwardProto),
			Type:     routeType,
			Policy:   row.dwForwardPolicy,
		})
		return true
	})
	return out
}

// DeleteRouteEntry removes the route identified by target from the IP
// forwarding table. Requires administrator privileges.
//
// target format: "dest|mask|gateway" using IPv4 dotted-decimal notation,
// e.g. "192.168.1.0|255.255.255.0|192.168.1.1".
func DeleteRouteEntry(target string) error {
	parts := strings.SplitN(target, "|", 3)
	if len(parts) != 3 {
		return fmt.Errorf("invalid route target %q (expected dest|mask|gateway)", target)
	}
	destIP := net.ParseIP(parts[0]).To4()
	maskIP := net.ParseIP(parts[1]).To4()
	gwIP := net.ParseIP(parts[2]).To4()
	if destIP == nil || maskIP == nil || gwIP == nil {
		return fmt.Errorf("invalid IP in route target %q", target)
	}
	wantDest := ip4ToLE(destIP)
	wantMask := ip4ToLE(maskIP)
	wantGW := ip4ToLE(gwIP)

	// Re-read the table to find the matching full row for DeleteIpForwardEntry.
	buf := fetchForwardTable(false)
	if buf == nil {
		return fmt.Errorf("GetIpForwardTable: failed to read routing table")
	}
	var deleteErr error
	found := false
	forForwardRows(buf, func(row *mibIPForwardRow) bool {
		if row.dwForwardDest != wantDest ||
			row.dwForwardMask != wantMask ||
			row.dwForwardNextHop != wantGW {
			return true
		}
		found = true
		rc, _, _ := procDeleteIpForwardEntry.Call(uintptr(unsafe.Pointer(row)))
		if rc != 0 {
			deleteErr = fmt.Errorf("DeleteIpForwardEntry: %w", syscall.Errno(rc))
		}
		return false // stop
	})
	if !found {
		return fmt.Errorf("route not found: %s", target)
	}
	return deleteErr
}
