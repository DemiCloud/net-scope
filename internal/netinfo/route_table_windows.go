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

// ReadRouteTable returns all IPv4 forwarding-table entries from Windows,
// sorted by destination. Entries with type=invalid (2) are excluded.
func ReadRouteTable() []RouteEntry {
	var size uint32
	r, _, _ := procGetIpForwardTable.Call(0, uintptr(unsafe.Pointer(&size)), 0)
	const errInsufficientBuffer = 122
	if r != 0 && r != errInsufficientBuffer {
		return nil
	}
	if size == 0 {
		return nil
	}
	buf := make([]byte, size)
	r, _, _ = procGetIpForwardTable.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
		1, // bOrder: sort by destination
	)
	if r != 0 {
		return nil
	}
	numEntries := *(*uint32)(unsafe.Pointer(&buf[0]))
	rowSize := unsafe.Sizeof(mibIPForwardRow{})
	out := make([]RouteEntry, 0, numEntries)
	for i := uint32(0); i < numEntries; i++ {
		off := uintptr(4) + uintptr(i)*rowSize
		if off+rowSize > uintptr(len(buf)) {
			break
		}
		row := (*mibIPForwardRow)(unsafe.Pointer(&buf[off]))
		if row.dwForwardType == 2 { // invalid
			continue
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
	}
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
	var size uint32
	r, _, _ := procGetIpForwardTable.Call(0, uintptr(unsafe.Pointer(&size)), 0)
	const errInsufficientBuffer = 122
	if r != 0 && r != errInsufficientBuffer {
		return fmt.Errorf("GetIpForwardTable: %w", syscall.Errno(r))
	}
	if size == 0 {
		return fmt.Errorf("routing table is empty")
	}
	buf := make([]byte, size)
	r, _, _ = procGetIpForwardTable.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
		0,
	)
	if r != 0 {
		return fmt.Errorf("GetIpForwardTable: %w", syscall.Errno(r))
	}
	numEntries := *(*uint32)(unsafe.Pointer(&buf[0]))
	rowSize := unsafe.Sizeof(mibIPForwardRow{})
	for i := uint32(0); i < numEntries; i++ {
		off := uintptr(4) + uintptr(i)*rowSize
		if off+rowSize > uintptr(len(buf)) {
			break
		}
		row := (*mibIPForwardRow)(unsafe.Pointer(&buf[off]))
		if row.dwForwardDest == wantDest &&
			row.dwForwardMask == wantMask &&
			row.dwForwardNextHop == wantGW {
			rc, _, _ := procDeleteIpForwardEntry.Call(uintptr(unsafe.Pointer(row)))
			if rc != 0 {
				return fmt.Errorf("DeleteIpForwardEntry: %w", syscall.Errno(rc))
			}
			return nil
		}
	}
	return fmt.Errorf("route not found: %s", target)
}
