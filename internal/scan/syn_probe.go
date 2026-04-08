//go:build !windows

package scan

import (
	"context"
	"encoding/binary"
	"math/rand"
	"net"
	"syscall"
	"time"
)

// probeSYN sends a raw TCP SYN to ip:port, reads the SYN-ACK, and returns the
// remote initial window size and TCP options string. Requires CAP_NET_RAW on
// Linux (or equivalent); degrades gracefully to empty SYNProbeInfo on
// permission error, timeout, or non-IPv4 address.
//
// Only the first SYN-ACK matching our (srcPort, seqNum) probe is returned.
// The kernel will automatically RST the half-open connection since nothing is
// listening on our random source port — this is expected and harmless.
func probeSYN(ctx context.Context, ip net.IP, port int, timeout time.Duration) SYNProbeInfo {
	ip4 := ip.To4()
	if ip4 == nil {
		return SYNProbeInfo{}
	}

	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	if err != nil {
		return SYNProbeInfo{}
	}
	defer syscall.Close(fd)

	if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1); err != nil {
		return SYNProbeInfo{}
	}

	// Bound receive wait to the caller's timeout.
	tv := syscall.NsecToTimeval(timeout.Nanoseconds())
	_ = syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)

	srcPort := uint16(49152 + rand.Intn(16383))
	seqNum := rand.Uint32()

	localIP := localIPFor(ip4)
	pkt := buildSYNPacket(localIP, ip4, srcPort, uint16(port), seqNum)

	dst := syscall.SockaddrInet4{Port: port}
	copy(dst.Addr[:], ip4)

	if err := syscall.Sendto(fd, pkt, 0, &dst); err != nil {
		return SYNProbeInfo{}
	}

	buf := make([]byte, 1500)
	for {
		if ctx.Err() != nil {
			return SYNProbeInfo{}
		}
		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			return SYNProbeInfo{} // SO_RCVTIMEO expired or other error
		}
		if info, ok := parseSYNACK(buf[:n], ip4, srcPort); ok {
			return info
		}
		// Non-matching packet (different flow); keep reading.
	}
}

// buildSYNPacket crafts a 60-byte IPv4/TCP SYN packet with options.
// Options: MSS(1460) SACK-permitted Timestamp NOP WScale(7) — 20 bytes.
func buildSYNPacket(srcIP, dstIP net.IP, srcPort, dstPort uint16, seqNum uint32) []byte {
	pkt := make([]byte, 60) // 20 IP + 20 TCP + 20 opts

	// --- IP header ---
	pkt[0] = 0x45 // version=4, IHL=5
	// [1] DSCP/ECN = 0
	binary.BigEndian.PutUint16(pkt[2:4], 60)
	binary.BigEndian.PutUint16(pkt[4:6], uint16(rand.Uint32()))
	pkt[6] = 0x40 // DF bit set
	pkt[8] = 64   // TTL
	pkt[9] = 6    // Protocol TCP
	// [10:12] checksum computed below
	copy(pkt[12:16], srcIP.To4())
	copy(pkt[16:20], dstIP.To4())

	// --- TCP header at offset 20 ---
	tcp := pkt[20:]
	binary.BigEndian.PutUint16(tcp[0:2], srcPort)
	binary.BigEndian.PutUint16(tcp[2:4], dstPort)
	binary.BigEndian.PutUint32(tcp[4:8], seqNum)
	// [8:12] ack = 0
	tcp[12] = 0xA0 // data offset = 10 (40 bytes total TCP)
	tcp[13] = 0x02 // SYN
	binary.BigEndian.PutUint16(tcp[14:16], 65535) // window
	// [16:18] checksum computed below
	// [18:20] urgent = 0

	// --- TCP options (20 bytes) ---
	opts := tcp[20:]
	// MSS 1460: kind=2 len=4
	opts[0], opts[1], opts[2], opts[3] = 2, 4, 0x05, 0xB4
	// SACK permitted: kind=4 len=2
	opts[4], opts[5] = 4, 2
	// Timestamp: kind=8 len=10, TSval=0xFFFFFFFF, TSecr=0
	opts[6], opts[7] = 8, 10
	binary.BigEndian.PutUint32(opts[8:12], 0xFFFFFFFF)
	// opts[12:16] = 0 (TSecr)
	// NOP
	opts[16] = 1
	// Window Scale: kind=3 len=3 value=7
	opts[17], opts[18], opts[19] = 3, 3, 7

	// Checksums
	binary.BigEndian.PutUint16(pkt[10:12], internetChecksum(pkt[:20]))
	binary.BigEndian.PutUint16(tcp[16:18], tcpChecksum(srcIP.To4(), dstIP.To4(), tcp[:40]))

	return pkt
}
