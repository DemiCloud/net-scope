package scan

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
)

// parseSYNACK extracts SYNProbeInfo from a raw IP packet if it is a TCP
// SYN-ACK sourced from targetIP. If ourSrcPort is non-zero, the packet's
// destination port must match it (Linux: we know our random source port).
// When ourSrcPort is 0, the destination-port check is skipped (Windows: the
// kernel picks the ephemeral port and we don't know it in advance).
func parseSYNACK(buf []byte, targetIP net.IP, ourSrcPort uint16) (SYNProbeInfo, bool) {
	if len(buf) < 40 {
		return SYNProbeInfo{}, false
	}
	ihl := int(buf[0]&0x0F) * 4
	if len(buf) < ihl+20 {
		return SYNProbeInfo{}, false
	}

	// Must be TCP (protocol field in IP header).
	if buf[9] != 6 {
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

	// Optionally filter by destination port (our ephemeral source port).
	if ourSrcPort != 0 && binary.BigEndian.Uint16(tcp[2:4]) != ourSrcPort {
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
