//go:build windows

package scan

import (
	"fmt"
	"net"
	"syscall"
	"unsafe"
)

var (
	procDeleteIpNetEntry = iphlpapi.NewProc("DeleteIpNetEntry")
	procFlushIpNetTable  = iphlpapi.NewProc("FlushIpNetTable")
)

// DeleteARPEntry removes the ARP table entry for the given IPv4 address.
// Requires administrator privileges.
func DeleteARPEntry(ipStr string) error {
	ip := net.ParseIP(ipStr).To4()
	if ip == nil {
		return fmt.Errorf("invalid IPv4 address: %s", ipStr)
	}
	target := uint32(ip[0]) | uint32(ip[1])<<8 | uint32(ip[2])<<16 | uint32(ip[3])<<24

	// Re-read the table to find the matching row so we can build the full
	// MIB_IPNETROW (DeleteIpNetEntry requires the interface index).
	var size uint32
	r, _, _ := procGetIpNetTable.Call(0, uintptr(unsafe.Pointer(&size)), 0)
	const errInsufficientBuffer = 122
	if r != 0 && r != errInsufficientBuffer {
		return fmt.Errorf("GetIpNetTable: %w", syscall.Errno(r))
	}
	if size == 0 {
		return fmt.Errorf("ARP table is empty")
	}
	buf := make([]byte, size)
	r, _, _ = procGetIpNetTable.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
		0,
	)
	if r != 0 {
		return fmt.Errorf("GetIpNetTable: %w", syscall.Errno(r))
	}

	numEntries := *(*uint32)(unsafe.Pointer(&buf[0]))
	rowSize := unsafe.Sizeof(mibIPNetRow{})
	for i := uint32(0); i < numEntries; i++ {
		off := uintptr(4) + uintptr(i)*rowSize
		if off+rowSize > uintptr(len(buf)) {
			break
		}
		row := (*mibIPNetRow)(unsafe.Pointer(&buf[off]))
		if row.Addr != target || row.PhysAddrLen != 6 {
			continue
		}
		rc, _, _ := procDeleteIpNetEntry.Call(uintptr(unsafe.Pointer(row)))
		if rc != 0 {
			return fmt.Errorf("DeleteIpNetEntry: %w", syscall.Errno(rc))
		}
		return nil
	}
	return fmt.Errorf("ARP entry not found for %s", ipStr)
}

// FlushARPCache clears all dynamic ARP entries. Pass ifIndex=0 to flush all
// interfaces. Requires administrator privileges.
func FlushARPCache(ifIndex uint32) error {
	r, _, _ := procFlushIpNetTable.Call(uintptr(ifIndex))
	if r != 0 {
		return fmt.Errorf("FlushIpNetTable: %w", syscall.Errno(r))
	}
	return nil
}
