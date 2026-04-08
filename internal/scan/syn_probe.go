//go:build !windows

package scan

import (
	"context"
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"strings"
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

// parseSYNACK extracts SYNProbeInfo from a raw IP packet if it is a SYN-ACK
// addressed to ourSrcPort and sourced from targetIP.
func parseSYNACK(buf []byte, targetIP net.IP, ourSrcPort uint16) (SYNProbeInfo, bool) {
	if len(buf) < 40 {
		return SYNProbeInfo{}, false
	}
	ihl := int(buf[0]&0x0F) * 4
	if len(buf) < ihl+20 {
		return SYNProbeInfo{}, false
	}

	// Source IP must be our target.
	if !net.IP(buf[12:16]).Equal(targetIP) {
		return SYNProbeInfo{}, false
	}

	tcp := buf[ihl:]
	if len(tcp) < 20 {
		return SYNProbeInfo{}, false
	}
	// Destination port must match our random source port.
	if binary.BigEndian.Uint16(tcp[2:4]) != ourSrcPort {
		return SYNProbeInfo{}, false
	}
	// Flags must be SYN+ACK (0x12).
	if tcp[13]&0x12 != 0x12 {
		return SYNProbeInfo{}, false
	}

	window := binary.BigEndian.Uint16(tcp[14:16])

	dataOff := int((tcp[12] >> 4) * 4)
	if dataOff < 20 || ihl+dataOff > len(buf) {
		return SYNProbeInfo{WindowSize: window}, true
	}

	opts := parseTCPOpts(tcp[20:dataOff])
	return SYNProbeInfo{WindowSize: window, Options: opts}, true
}

// parseTCPOpts walks TCP option bytes and returns a human-readable string
// listing the options in order, e.g. "MSS(1460) SACK TS NOP WScale(7)".
func parseTCPOpts(opts []byte) string {
	var parts []string
	i := 0
	for i < len(opts) {
		kind := opts[i]
		if kind == 0 { // EOL
			break
		}
		if kind == 1 { // NOP
			parts = append(parts, "NOP")
			i++
			continue
		}
		if i+1 >= len(opts) {
			break
		}
		length := int(opts[i+1])
		if length < 2 || i+length > len(opts) {
			break
		}
		switch kind {
		case 2: // MSS
			if length == 4 {
				mss := binary.BigEndian.Uint16(opts[i+2 : i+4])
				parts = append(parts, fmt.Sprintf("MSS(%d)", mss))
			}
		case 3: // Window Scale
			if length == 3 {
				parts = append(parts, fmt.Sprintf("WScale(%d)", opts[i+2]))
			}
		case 4: // SACK permitted
			parts = append(parts, "SACK")
		case 8: // Timestamps
			parts = append(parts, "TS")
		default:
			parts = append(parts, fmt.Sprintf("Opt%d", kind))
		}
		i += length
	}
	return strings.Join(parts, " ")
}

// localIPFor returns the local IPv4 address used to reach dst, or 0.0.0.0.
func localIPFor(dst net.IP) net.IP {
	conn, err := net.Dial("udp4", fmt.Sprintf("%s:1", dst))
	if err != nil {
		return net.IPv4(0, 0, 0, 0).To4()
	}
	defer conn.Close()
	ip := conn.LocalAddr().(*net.UDPAddr).IP.To4()
	if ip == nil {
		return net.IPv4(0, 0, 0, 0).To4()
	}
	return ip
}

// internetChecksum computes the RFC 791 ones' complement checksum.
func internetChecksum(b []byte) uint16 {
	sum := uint32(0)
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i : i+2]))
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}

// tcpChecksum computes the TCP checksum over the pseudo-header and segment.
func tcpChecksum(srcIP, dstIP []byte, segment []byte) uint16 {
	pseudo := make([]byte, 12)
	copy(pseudo[0:4], srcIP)
	copy(pseudo[4:8], dstIP)
	pseudo[9] = 6 // TCP
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(segment)))
	return internetChecksumMulti(pseudo, segment)
}

// internetChecksumMulti is internetChecksum across multiple byte slices.
func internetChecksumMulti(parts ...[]byte) uint16 {
	sum := uint32(0)
	for _, b := range parts {
		for i := 0; i+1 < len(b); i += 2 {
			sum += uint32(binary.BigEndian.Uint16(b[i : i+2]))
		}
		if len(b)%2 == 1 {
			sum += uint32(b[len(b)-1]) << 8
		}
	}
	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}
