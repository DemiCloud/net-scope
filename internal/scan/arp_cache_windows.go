//go:build windows

package scan

import (
	"net"
	"syscall"
	"unsafe"
)

var (
	iphlpapi          = syscall.NewLazyDLL("iphlpapi.dll")
	procSendARP       = iphlpapi.NewProc("SendARP")
	procGetIpNetTable = iphlpapi.NewProc("GetIpNetTable")
)

// mibIPNetRow mirrors the Windows MIB_IPNETROW structure (24 bytes, no padding).
type mibIPNetRow struct {
	Index       uint32
	PhysAddrLen uint32
	PhysAddr    [8]byte // MAXLEN_PHYSADDR=8; first PhysAddrLen bytes are the MAC
	Addr        uint32  // IPv4 in network byte order (on LE: a|b<<8|c<<16|d<<24)
	Type        uint32  // 1=other 2=invalid 3=dynamic 4=static
}

// lookupARPCache tries two strategies in order:
//  1. Read the Windows ARP neighbor table (GetIpNetTable) — populated as a side-effect
//     of the ICMP ping, no network I/O, fast.
//  2. Send a fresh ARP request (SendARP) — works if the host is on a local subnet.
//
// Returns nil if the MAC cannot be determined (e.g. host is on a remote subnet).
func lookupARPCache(ip net.IP) net.HardwareAddr {
	ip4 := ip.To4()
	if ip4 == nil {
		return nil
	}
	// Encode as the uint32 value we will read back from mibIPNetRow.Addr on LE Windows:
	//   bytes in memory = [ip4[0], ip4[1], ip4[2], ip4[3]]  (network byte order)
	//   uint32 on LE    = ip4[0] | ip4[1]<<8 | ip4[2]<<16 | ip4[3]<<24
	target := uint32(ip4[0]) | uint32(ip4[1])<<8 | uint32(ip4[2])<<16 | uint32(ip4[3])<<24

	if mac := readARPTable(target); mac != nil {
		return mac
	}
	return sendARPRequest(target)
}

// readARPTable queries GetIpNetTable and returns the MAC for target, or nil.
func readARPTable(target uint32) net.HardwareAddr {
	// First call: get required buffer size.
	var size uint32
	r, _, _ := procGetIpNetTable.Call(0, uintptr(unsafe.Pointer(&size)), 0)
	const errInsufficientBuffer = 122
	if r != 0 && r != errInsufficientBuffer {
		return nil
	}
	if size == 0 {
		return nil
	}

	buf := make([]byte, size)
	r, _, _ = procGetIpNetTable.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
		0, // bOrder=FALSE (unsorted)
	)
	if r != 0 {
		return nil
	}

	numEntries := *(*uint32)(unsafe.Pointer(&buf[0]))
	rowSize := unsafe.Sizeof(mibIPNetRow{})
	for i := uint32(0); i < numEntries; i++ {
		off := uintptr(4) + uintptr(i)*rowSize
		if off+rowSize > uintptr(len(buf)) {
			break
		}
		row := (*mibIPNetRow)(unsafe.Pointer(&buf[off]))
		if row.Addr == target && row.PhysAddrLen == 6 && row.Type != 2 {
			mac := make(net.HardwareAddr, 6)
			copy(mac, row.PhysAddr[:6])
			return mac
		}
	}
	return nil
}

// sendARPRequest uses the Windows SendARP API to send an ARP request.
// This works without admin rights and returns the reply MAC.
// Fails quickly for remote-subnet hosts (Windows returns an error immediately).
func sendARPRequest(target uint32) net.HardwareAddr {
	var macBuf [2]uint32 // 8 bytes; SendARP writes 6-byte MAC at the front
	macLen := uint32(6)

	r, _, _ := procSendARP.Call(
		uintptr(target),
		0, // SrcIP=0 → OS picks the interface
		uintptr(unsafe.Pointer(&macBuf[0])),
		uintptr(unsafe.Pointer(&macLen)),
	)
	if r != 0 || macLen < 6 {
		return nil
	}

	mac := make(net.HardwareAddr, 6)
	copy(mac, (*[8]byte)(unsafe.Pointer(&macBuf[0]))[:6])
	return mac
}

// ReadARPTableFull returns all valid ARP table entries including type and
// interface-index metadata. Entries with invalid MACs or type=invalid are
// skipped. Returns nil on any error.
func ReadARPTableFull() []ARPResult {
	var size uint32
	r, _, _ := procGetIpNetTable.Call(0, uintptr(unsafe.Pointer(&size)), 0)
	const errInsufficientBuffer = 122
	if r != 0 && r != errInsufficientBuffer {
		return nil
	}
	if size == 0 {
		return nil
	}
	buf := make([]byte, size)
	r, _, _ = procGetIpNetTable.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
		0,
	)
	if r != 0 {
		return nil
	}
	numEntries := *(*uint32)(unsafe.Pointer(&buf[0]))
	rowSize := unsafe.Sizeof(mibIPNetRow{})
	out := make([]ARPResult, 0, numEntries)
	for i := uint32(0); i < numEntries; i++ {
		off := uintptr(4) + uintptr(i)*rowSize
		if off+rowSize > uintptr(len(buf)) {
			break
		}
		row := (*mibIPNetRow)(unsafe.Pointer(&buf[off]))
		if row.Type == 2 || row.PhysAddrLen != 6 {
			continue // skip invalid entries and non-Ethernet MACs
		}
		ip := net.IP{byte(row.Addr), byte(row.Addr >> 8), byte(row.Addr >> 16), byte(row.Addr >> 24)}
		mac := make(net.HardwareAddr, 6)
		copy(mac, row.PhysAddr[:6])
		arpType := "other"
		switch row.Type {
		case 3:
			arpType = "dynamic"
		case 4:
			arpType = "static"
		}
		out = append(out, ARPResult{
			IP:      ip.String(),
			MAC:     mac.String(),
			Type:    arpType,
			IfIndex: row.Index,
		})
	}
	return out
}

// ReadARPTable returns a snapshot of the Windows ARP neighbour table as
// IPv4-string → MAC. Only valid (type 3 dynamic, type 4 static) Ethernet
// entries are included. Returns nil on any error.
func ReadARPTable() map[string]net.HardwareAddr {
	var size uint32
	r, _, _ := procGetIpNetTable.Call(0, uintptr(unsafe.Pointer(&size)), 0)
	const errInsufficientBuffer = 122
	if r != 0 && r != errInsufficientBuffer {
		return nil
	}
	if size == 0 {
		return nil
	}
	buf := make([]byte, size)
	r, _, _ = procGetIpNetTable.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
		0,
	)
	if r != 0 {
		return nil
	}
	numEntries := *(*uint32)(unsafe.Pointer(&buf[0]))
	rowSize := unsafe.Sizeof(mibIPNetRow{})
	out := make(map[string]net.HardwareAddr, numEntries)
	for i := uint32(0); i < numEntries; i++ {
		off := uintptr(4) + uintptr(i)*rowSize
		if off+rowSize > uintptr(len(buf)) {
			break
		}
		row := (*mibIPNetRow)(unsafe.Pointer(&buf[off]))
		// Skip invalid entries and non-Ethernet MACs.
		if row.Type == 2 || row.PhysAddrLen != 6 {
			continue
		}
		// Addr is in LE uint32: bytes in memory are network order.
		ip := net.IP{byte(row.Addr), byte(row.Addr >> 8), byte(row.Addr >> 16), byte(row.Addr >> 24)}
		mac := make(net.HardwareAddr, 6)
		copy(mac, row.PhysAddr[:6])
		out[ip.String()] = mac
	}
	return out
}
