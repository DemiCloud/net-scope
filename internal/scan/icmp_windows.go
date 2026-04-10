//go:build windows

package scan

import (
	"context"
	"net"
	"syscall"
	"time"
	"unsafe"
)

var (
	modIphlpapi        = syscall.NewLazyDLL("iphlpapi.dll")
	procIcmpCreateFile = modIphlpapi.NewProc("IcmpCreateFile")
	procIcmpCloseHandle = modIphlpapi.NewProc("IcmpCloseHandle")
	procIcmpSendEcho   = modIphlpapi.NewProc("IcmpSendEcho")
)

// icmpEchoReply mirrors the Windows ICMP_ECHO_REPLY structure (64-bit layout).
// https://docs.microsoft.com/en-us/windows/win32/api/ipexport/ns-ipexport-icmp_echo_reply
type icmpEchoReply struct {
	Address       uint32  // replying IPv4 address
	Status        uint32  // 0 = IP_SUCCESS
	RoundTripTime uint32  // round-trip time in milliseconds
	DataSize      uint16
	Reserved      uint16
	Data          uintptr // pointer into reply buffer
	// IP_OPTION_INFORMATION (inline)
	Ttl         uint8
	Tos         uint8
	Flags       uint8
	OptionsSize uint8
	_           [4]byte // padding before pointer (64-bit)
	OptionsData uintptr
}

// ping sends a single ICMP echo request via the Windows IcmpSendEcho API.
// This does not require npcap or raw socket privileges; it works on any
// process that can open a regular ICMP handle.
func ping(ctx context.Context, ip net.IP, timeout time.Duration) (time.Duration, uint8, bool) {
	if ctx.Err() != nil {
		return 0, 0, false
	}

	ip4 := ip.To4()
	if ip4 == nil {
		return 0, 0, false
	}

	h, _, _ := procIcmpCreateFile.Call()
	const invalidHandle = ^uintptr(0) // INVALID_HANDLE_VALUE
	if h == 0 || h == invalidHandle {
		return 0, 0, false
	}
	defer procIcmpCloseHandle.Call(h)

	// IcmpSendEcho expects DestinationAddress as IPAddr (ULONG), which matches the
	// in_addr / inet_addr convention on little-endian Windows: the four IP octets are
	// laid out in memory in network order (a,b,c,d), so the ULONG integer value is
	// little-endian (e.g. 192.168.1.1 → 0x0101A8C0). This matches GetIpNetTable's
	// Addr field — see arp_cache_windows.go for the same encoding.
	dest := uint32(ip4[0]) | uint32(ip4[1])<<8 | uint32(ip4[2])<<16 | uint32(ip4[3])<<24

	reqData := []byte("net-scope")
	// Reply buffer must be sizeof(ICMP_ECHO_REPLY) + requestSize + 8 (MSDN).
	replyBufSize := unsafe.Sizeof(icmpEchoReply{}) + uintptr(len(reqData)) + 8
	replyBuf := make([]byte, replyBufSize)

	ms := uint32(timeout.Milliseconds())
	if ms == 0 {
		ms = 1000
	}

	start := time.Now()
	n, _, _ := procIcmpSendEcho.Call(
		h,
		uintptr(dest),
		uintptr(unsafe.Pointer(&reqData[0])),
		uintptr(len(reqData)),
		0, // RequestOptions = NULL
		uintptr(unsafe.Pointer(&replyBuf[0])),
		replyBufSize,
		uintptr(ms),
	)
	elapsed := time.Since(start)

	if n == 0 {
		return 0, 0, false
	}
	reply := (*icmpEchoReply)(unsafe.Pointer(&replyBuf[0]))
	if reply.Status != 0 {
		return 0, 0, false
	}
	return elapsed, reply.Ttl, true
}
