//go:build windows

package netinfo

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

// fetchIPNetTable calls GetIpNetTable twice (size-query then data-query) and
// returns the raw buffer on success, or nil on error. It retries up to 3 times
// if the table grows between the two calls (TOCTOU ERROR_INSUFFICIENT_BUFFER).
func fetchIPNetTable() []byte {
	var size uint32
	r, _, _ := procGetIpNetTable.Call(0, uintptr(unsafe.Pointer(&size)), 0)
	const errInsufficientBuffer = 122
	if r != 0 && r != errInsufficientBuffer {
		return nil
	}
	if size == 0 {
		return nil
	}
	for range 3 {
		buf := make([]byte, size)
		r, _, _ = procGetIpNetTable.Call(
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(unsafe.Pointer(&size)),
			0,
		)
		if r == 0 {
			return buf
		}
		if r != errInsufficientBuffer {
			return nil
		}
		// size was updated by the failed call; retry with the new value.
	}
	return nil
}

// forIPNetRows calls fn for each MIB_IPNETROW in buf (a GetIpNetTable result).
// If fn returns false, iteration stops.
func forIPNetRows(buf []byte, fn func(*mibIPNetRow) bool) {
	if len(buf) < 4 {
		return
	}
	numEntries := *(*uint32)(unsafe.Pointer(&buf[0]))
	rowSize := unsafe.Sizeof(mibIPNetRow{})
	for i := uint32(0); i < numEntries; i++ {
		off := uintptr(4) + uintptr(i)*rowSize
		if off+rowSize > uintptr(len(buf)) {
			break
		}
		if !fn((*mibIPNetRow)(unsafe.Pointer(&buf[off]))) {
			return
		}
	}
}

// LookupARPCache tries two strategies in order:
//  1. Read the Windows ARP neighbor table (GetIpNetTable) — populated as a side-effect
//     of the ICMP ping, no network I/O, fast.
//  2. Send a fresh ARP request (SendARP) — works if the host is on a local subnet.
//
// Returns nil if the MAC cannot be determined (e.g. host is on a remote subnet).
func LookupARPCache(ip net.IP) net.HardwareAddr {
	ip4 := ip.To4()
	if ip4 == nil {
		return nil
	}
	target := ip4ToLE(ip4)
	if mac := readARPTable(target); mac != nil {
		return mac
	}
	return sendARPRequest(target)
}

// readARPTable queries GetIpNetTable and returns the MAC for target, or nil.
func readARPTable(target uint32) net.HardwareAddr {
	buf := fetchIPNetTable()
	if buf == nil {
		return nil
	}
	var found net.HardwareAddr
	forIPNetRows(buf, func(row *mibIPNetRow) bool {
		if row.Addr == target && row.PhysAddrLen == 6 && row.Type != 2 {
			mac := make(net.HardwareAddr, 6)
			copy(mac, row.PhysAddr[:6])
			found = mac
			return false // stop iteration
		}
		return true
	})
	return found
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
	buf := fetchIPNetTable()
	if buf == nil {
		return nil
	}
	var out []ARPResult
	forIPNetRows(buf, func(row *mibIPNetRow) bool {
		if row.Type == 2 || row.PhysAddrLen != 6 {
			return true // skip invalid entries and non-Ethernet MACs
		}
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
			IP:      ip4FromLE(row.Addr).String(),
			MAC:     mac.String(),
			Type:    arpType,
			IfIndex: row.Index,
		})
		return true
	})
	return out
}

// ReadARPTable returns a snapshot of the Windows ARP neighbour table as
// IPv4-string → MAC. Only valid (type 3 dynamic, type 4 static) Ethernet
// entries are included. Returns nil on any error.
func ReadARPTable() map[string]net.HardwareAddr {
	buf := fetchIPNetTable()
	if buf == nil {
		return nil
	}
	out := make(map[string]net.HardwareAddr)
	forIPNetRows(buf, func(row *mibIPNetRow) bool {
		if row.Type == 2 || row.PhysAddrLen != 6 {
			return true // skip invalid entries and non-Ethernet MACs
		}
		mac := make(net.HardwareAddr, 6)
		copy(mac, row.PhysAddr[:6])
		out[ip4FromLE(row.Addr).String()] = mac
		return true
	})
	return out
}
