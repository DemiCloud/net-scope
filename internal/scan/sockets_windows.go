//go:build windows

package scan

import (
	"fmt"
	"math/bits"
	"net"
	"strings"
	"syscall"
	"unsafe"
)

var (
	procGetExtendedTcpTable        = iphlpapi.NewProc("GetExtendedTcpTable")
	procGetExtendedUdpTable        = iphlpapi.NewProc("GetExtendedUdpTable")
	procOpenProcess                 = kernel32DLL.NewProc("OpenProcess")
	procQueryFullProcessImageNameW  = kernel32DLL.NewProc("QueryFullProcessImageNameW")
	procCloseHandle                 = kernel32DLL.NewProc("CloseHandle")
)

// ---------------------------------------------------------------------------
// Struct mirrors for Windows extended TCP/UDP table rows
// ---------------------------------------------------------------------------

// mibTcpRowOwnerPID mirrors MIB_TCPROW_OWNER_PID (24 bytes).
type mibTcpRowOwnerPID struct {
	State      uint32
	LocalAddr  uint32
	LocalPort  uint32 // network byte order in low 16 bits
	RemoteAddr uint32
	RemotePort uint32
	OwningPID  uint32
}

// mibTcp6RowOwnerPID mirrors MIB_TCP6ROW_OWNER_PID (56 bytes).
type mibTcp6RowOwnerPID struct {
	LocalAddr     [16]byte
	LocalScopeId  uint32
	LocalPort     uint32
	RemoteAddr    [16]byte
	RemoteScopeId uint32
	RemotePort    uint32
	State         uint32
	OwningPID     uint32
}

// mibUdpRowOwnerPID mirrors MIB_UDPROW_OWNER_PID (12 bytes).
type mibUdpRowOwnerPID struct {
	LocalAddr uint32
	LocalPort uint32
	OwningPID uint32
}

// mibUdp6RowOwnerPID mirrors MIB_UDP6ROW_OWNER_PID (28 bytes).
type mibUdp6RowOwnerPID struct {
	LocalAddr    [16]byte
	LocalScopeId uint32
	LocalPort    uint32
	OwningPID    uint32
}

const (
	tcpTableOwnerPIDAll = 5 // GetExtendedTcpTable TableClass for all PID rows
	udpTableOwnerPID    = 1 // GetExtendedUdpTable TableClass for PID rows
	afINET              = 2
	afINET6             = 23

	winProcQueryLimited uint32 = 0x1000 // PROCESS_QUERY_LIMITED_INFORMATION
)

var winTCPStates = map[uint32]string{
	1: "CLOSED", 2: "LISTEN", 3: "SYN_SENT", 4: "SYN_RECEIVED",
	5: "ESTABLISHED", 6: "FIN_WAIT_1", 7: "FIN_WAIT_2",
	8: "CLOSE_WAIT", 9: "CLOSING", 10: "LAST_ACK",
	11: "TIME_WAIT", 12: "DELETE_TCB",
}

// winPortHost converts a Windows extended-table DWORD port (network byte order
// in the low 16 bits) to a host-order uint16.
func winPortHost(dword uint32) uint16 {
	return bits.ReverseBytes16(uint16(dword))
}

// lookupWinProcessName opens the process with PROCESS_QUERY_LIMITED_INFORMATION
// and queries its image file name.  Returns "[pid]" on failure.
func lookupWinProcessName(pid uint32) string {
	if pid == 0 {
		return "[Idle]"
	}
	if pid == 4 {
		return "System"
	}
	h, _, _ := procOpenProcess.Call(uintptr(winProcQueryLimited), 0, uintptr(pid))
	if h == 0 {
		return fmt.Sprintf("[%d]", pid)
	}
	defer procCloseHandle.Call(h)

	buf := make([]uint16, 260)
	size := uint32(len(buf))
	r, _, _ := procQueryFullProcessImageNameW.Call(
		h, 0, uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)),
	)
	if r == 0 {
		return fmt.Sprintf("[%d]", pid)
	}
	full := syscall.UTF16ToString(buf[:size])
	if idx := strings.LastIndexByte(full, '\\'); idx >= 0 {
		return full[idx+1:]
	}
	return full
}

// extendedTableBuf calls GetExtendedTcpTable or GetExtendedUdpTable, allocating
// and growing the buffer until it fits.
func extendedTableBuf(proc *syscall.LazyProc, af, tableClass uint32) []byte {
	var size uint32
	const errInsufficient = 122
	r, _, _ := proc.Call(0, uintptr(unsafe.Pointer(&size)), 0,
		uintptr(af), uintptr(tableClass), 0)
	if r != 0 && r != errInsufficient {
		return nil
	}
	if size == 0 {
		return nil
	}
	for {
		buf := make([]byte, size)
		r, _, _ = proc.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)),
			0, uintptr(af), uintptr(tableClass), 0)
		if r == 0 {
			return buf
		}
		if r == errInsufficient {
			continue // size was updated — retry
		}
		return nil
	}
}

// ReadSockets returns a snapshot of all TCP and UDP sockets with their PIDs
// and process names. Returns nil on error or if the APIs are unavailable.
func ReadSockets() []SocketEntry {
	pidNames := map[uint32]string{}
	getName := func(pid uint32) string {
		if n, ok := pidNames[pid]; ok {
			return n
		}
		n := lookupWinProcessName(pid)
		pidNames[pid] = n
		return n
	}

	var out []SocketEntry

	// TCP IPv4
	if buf := extendedTableBuf(procGetExtendedTcpTable, afINET, tcpTableOwnerPIDAll); buf != nil {
		n := *(*uint32)(unsafe.Pointer(&buf[0]))
		sz := unsafe.Sizeof(mibTcpRowOwnerPID{})
		for i := uint32(0); i < n; i++ {
			off := uintptr(4) + uintptr(i)*sz
			if off+sz > uintptr(len(buf)) {
				break
			}
			r := (*mibTcpRowOwnerPID)(unsafe.Pointer(&buf[off]))
			state := winTCPStates[r.State]
			laddr := ip4FromLE(r.LocalAddr).String()
			raddr := ""
			var rport uint16
			if r.State != 2 { // not LISTEN
				raddr = ip4FromLE(r.RemoteAddr).String()
				rport = winPortHost(r.RemotePort)
			}
			out = append(out, SocketEntry{
				Proto: "TCP", LocalAddr: laddr, LocalPort: winPortHost(r.LocalPort),
				RemoteAddr: raddr, RemotePort: rport,
				State: state, PID: r.OwningPID, Process: getName(r.OwningPID),
			})
		}
	}

	// TCP IPv6
	if buf := extendedTableBuf(procGetExtendedTcpTable, afINET6, tcpTableOwnerPIDAll); buf != nil {
		n := *(*uint32)(unsafe.Pointer(&buf[0]))
		sz := unsafe.Sizeof(mibTcp6RowOwnerPID{})
		for i := uint32(0); i < n; i++ {
			off := uintptr(4) + uintptr(i)*sz
			if off+sz > uintptr(len(buf)) {
				break
			}
			r := (*mibTcp6RowOwnerPID)(unsafe.Pointer(&buf[off]))
			state := winTCPStates[r.State]
			laddr := networkIPv6(r.LocalAddr)
			raddr := ""
			var rport uint16
			if r.State != 2 { // not LISTEN
				raddr = networkIPv6(r.RemoteAddr)
				rport = winPortHost(r.RemotePort)
			}
			out = append(out, SocketEntry{
				Proto: "TCP6", LocalAddr: laddr, LocalPort: winPortHost(r.LocalPort),
				RemoteAddr: raddr, RemotePort: rport,
				State: state, PID: r.OwningPID, Process: getName(r.OwningPID),
			})
		}
	}

	// UDP IPv4
	if buf := extendedTableBuf(procGetExtendedUdpTable, afINET, udpTableOwnerPID); buf != nil {
		n := *(*uint32)(unsafe.Pointer(&buf[0]))
		sz := unsafe.Sizeof(mibUdpRowOwnerPID{})
		for i := uint32(0); i < n; i++ {
			off := uintptr(4) + uintptr(i)*sz
			if off+sz > uintptr(len(buf)) {
				break
			}
			r := (*mibUdpRowOwnerPID)(unsafe.Pointer(&buf[off]))
			out = append(out, SocketEntry{
				Proto: "UDP", LocalAddr: ip4FromLE(r.LocalAddr).String(),
				LocalPort: winPortHost(r.LocalPort),
				PID: r.OwningPID, Process: getName(r.OwningPID),
			})
		}
	}

	// UDP IPv6
	if buf := extendedTableBuf(procGetExtendedUdpTable, afINET6, udpTableOwnerPID); buf != nil {
		n := *(*uint32)(unsafe.Pointer(&buf[0]))
		sz := unsafe.Sizeof(mibUdp6RowOwnerPID{})
		for i := uint32(0); i < n; i++ {
			off := uintptr(4) + uintptr(i)*sz
			if off+sz > uintptr(len(buf)) {
				break
			}
			r := (*mibUdp6RowOwnerPID)(unsafe.Pointer(&buf[off]))
			out = append(out, SocketEntry{
				Proto: "UDP6", LocalAddr: networkIPv6(r.LocalAddr),
				LocalPort: winPortHost(r.LocalPort),
				PID: r.OwningPID, Process: getName(r.OwningPID),
			})
		}
	}

	return out
}

// networkIPv6 converts a raw 16-byte IPv6 address (in network byte order,
// as returned by Windows extended-table APIs) to a dotted notation string.
func networkIPv6(b [16]byte) string {
	ip := make([]byte, 16)
	copy(ip, b[:])
	return net.IP(ip).String()
}
