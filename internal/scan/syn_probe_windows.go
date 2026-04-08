//go:build windows

package scan

import (
	"context"
	"encoding/binary"
	"net"
	"strconv"
	"syscall"
	"time"
	"unsafe"
)

const (
	// SIO_RCVALL = _WSAIOW(IOC_VENDOR,1) = 0x98000001
	sioRcvAll = uint32(0x98000001)
	rcvAllOn  = uint32(1)

	// SO_RCVTIMEO is not exported by Go's windows syscall package; value from winsock2.h.
	soRcvTimeo = 0x1006
)

var (
	// ws2_32.dll is always present on Windows; no fallback needed.
	modWs2SYN      = syscall.NewLazyDLL("ws2_32.dll")
	procSetsockSYN = modWs2SYN.NewProc("setsockopt")
)

// probeSYN on Windows uses SIO_RCVALL promiscuous sniffing to capture the
// kernel's SYN-ACK during a real net.Dial handshake. This avoids raw TCP
// sends (blocked since Vista) without requiring WinPcap/Npcap.
//
// Mechanism:
//  1. Open an AF_INET/SOCK_RAW/IPPROTO_IP socket and bind it to the local
//     interface address that faces the target.
//  2. Enable SIO_RCVALL — socket now receives all incoming IP frames on
//     that interface (requires Administrator elevation).
//  3. Spin a goroutine that reads packets, filtering for a TCP SYN-ACK
//     from targetIP:port.
//  4. Call net.Dial to trigger the real kernel TCP handshake; the SYN-ACK
//     is visible on the raw socket.
//  5. Return the parsed window size and TCP options.
//
// Returns empty SYNProbeInfo when not elevated, target is not IPv4, or no
// SYN-ACK is received within timeout.
func probeSYN(ctx context.Context, ip net.IP, port int, timeout time.Duration) SYNProbeInfo {
	if !IsElevated() {
		return SYNProbeInfo{}
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return SYNProbeInfo{}
	}

	localIP := localIPFor(ip4)

	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_IP)
	if err != nil {
		return SYNProbeInfo{}
	}
	defer syscall.Closesocket(fd)

	// Bind to the local interface address; SIO_RCVALL requires a bound socket.
	lsa := &syscall.SockaddrInet4{}
	copy(lsa.Addr[:], localIP.To4())
	if err := syscall.Bind(fd, lsa); err != nil {
		return SYNProbeInfo{}
	}

	// Enable promiscuous receive. Windows SO_RCVTIMEO for raw sockets is
	// unreliable across versions; we rely on socket close (deferred above) to
	// unblock Recvfrom if no SYN-ACK arrives.
	mode := rcvAllOn
	var bytesRet uint32
	if err := syscall.WSAIoctl(
		fd, sioRcvAll,
		(*byte)(unsafe.Pointer(&mode)), uint32(unsafe.Sizeof(mode)),
		nil, 0,
		&bytesRet, nil, 0,
	); err != nil {
		return SYNProbeInfo{}
	}

	// Set SO_RCVTIMEO via direct setsockopt call. On Windows the value is a
	// DWORD (milliseconds), not struct timeval, so we bypass the Go wrapper.
	ms := int32(timeout.Milliseconds())
	if ms <= 0 {
		ms = 5000
	}
	procSetsockSYN.Call( //nolint:errcheck
		uintptr(fd),
		uintptr(syscall.SOL_SOCKET),
		soRcvTimeo,
		uintptr(unsafe.Pointer(&ms)),
		4, // sizeof(DWORD)
	)

	resultCh := make(chan SYNProbeInfo, 1)
	go func() {
		buf := make([]byte, 1500)
		targetPort := uint16(port)
		for {
			if ctx.Err() != nil {
				return
			}
			n, _, err := syscall.Recvfrom(fd, buf, 0)
			if err != nil {
				return // socket closed or timeout
			}
			if n < 20 {
				continue
			}
			// Quick pre-filter: must be TCP (proto=6) from our target IP.
			if buf[9] != 6 {
				continue
			}
			ihl := int(buf[0]&0x0F) * 4
			if n < ihl+4 {
				continue
			}
			// Source TCP port must be the port we're probing.
			if binary.BigEndian.Uint16(buf[ihl:ihl+2]) != targetPort {
				continue
			}
			// Full parse (verifies source IP, SYN+ACK flag, extracts options).
			// ourSrcPort=0: skip dst-port check (kernel chose it, we don't know it).
			if info, ok := parseSYNACK(buf[:n], ip4, 0); ok {
				select {
				case resultCh <- info:
				default:
				}
				return
			}
		}
	}()

	// Trigger the real kernel TCP handshake. The SYN-ACK is captured above
	// regardless of whether Dial ultimately succeeds.
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, dialErr := (&net.Dialer{}).DialContext(dialCtx, "tcp",
		net.JoinHostPort(ip.String(), strconv.Itoa(port)))
	if dialErr == nil {
		conn.Close()
	}

	select {
	case info := <-resultCh:
		return info
	case <-time.After(timeout):
		return SYNProbeInfo{}
	case <-ctx.Done():
		return SYNProbeInfo{}
	}
}

