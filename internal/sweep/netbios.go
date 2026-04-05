package sweep

import (
	"encoding/binary"
	"net"
	"strings"
	"time"
)

const (
	netbiosPort    = 137
	netbiosTimeout = 2 * time.Second
)

// probeNetBIOS queries a host's NetBIOS Name Service (UDP 137) and returns
// the workstation or server name, or "" if the host doesn't respond.
// This is a read-only query — equivalent to the `nbtstat -A` command.
func probeNetBIOS(ip net.IP, timeout time.Duration) string {
	conn, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: ip, Port: netbiosPort})
	if err != nil {
		return ""
	}
	defer conn.Close()

	if timeout > netbiosTimeout {
		timeout = netbiosTimeout
	}
	conn.SetDeadline(time.Now().Add(timeout))

	// NetBIOS Name Query Request (NODE STATUS)
	// Transaction ID = 0xAB01, flags=0x0000, questions=1, * (wildcard) name
	req := buildNetBIOSNodeStatus()
	if _, err := conn.Write(req); err != nil {
		return ""
	}

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil || n < 57 {
		return ""
	}

	return parseNetBIOSResponse(buf[:n])
}

// buildNetBIOSNodeStatus constructs a NODE STATUS REQUEST packet.
func buildNetBIOSNodeStatus() []byte {
	pkt := make([]byte, 50)

	// Transaction ID
	binary.BigEndian.PutUint16(pkt[0:], 0xAB01)
	// Flags: 0x0000 (query, non-recursive)
	binary.BigEndian.PutUint16(pkt[2:], 0x0000)
	// Questions: 1
	binary.BigEndian.PutUint16(pkt[4:], 0x0001)
	// Answer, authority, additional RRs: 0
	binary.BigEndian.PutUint16(pkt[6:], 0)
	binary.BigEndian.PutUint16(pkt[8:], 0)
	binary.BigEndian.PutUint16(pkt[10:], 0)

	// Encoded name: "*" (wildcard) + 15 spaces, encoded via NetBIOS encoding
	// NetBIOS name encoding adds 0x20 to each nibble → each byte splits to two chars
	offset := 12
	pkt[offset] = 0x20 // one label of length 32
	offset++
	// Wildcard name "*\x00\x00..." (16 bytes) encoded to 32 bytes
	name := make([]byte, 16)
	name[0] = '*'
	for i, b := range name {
		hi := (b >> 4) + 0x41
		lo := (b & 0x0F) + 0x41
		pkt[offset+i*2] = hi
		pkt[offset+i*2+1] = lo
	}
	offset += 32
	pkt[offset] = 0x00 // null terminator
	offset++

	// QTYPE = NBSTAT (0x0021), QCLASS = IN (0x0001)
	binary.BigEndian.PutUint16(pkt[offset:], 0x0021)
	binary.BigEndian.PutUint16(pkt[offset+2:], 0x0001)

	return pkt[:offset+4]
}

// parseNetBIOSResponse extracts the workstation name from a NODE STATUS RESPONSE.
func parseNetBIOSResponse(data []byte) string {
	// Minimum viable: need at least the header (12 bytes) + answer section.
	// The name table starts at byte 57 for a standard response.
	// Structure: 12-byte header + encoded question (34 bytes) + answer RR header (11 bytes)
	// → name count byte is at offset 57.
	if len(data) < 57 {
		return ""
	}

	// Number of names in the table
	numNames := int(data[56])
	if numNames == 0 || len(data) < 57+numNames*18 {
		return ""
	}

	// Each name entry is 18 bytes: 15-byte name + 1-byte type + 2-byte flags
	var workstation string
	for i := 0; i < numNames; i++ {
		entry := data[57+i*18 : 57+i*18+18]
		nameBytes := entry[0:15]
		nameType := entry[15]

		name := strings.TrimRight(string(nameBytes), " \x00")
		if name == "" {
			continue
		}

		// Type 0x00 = workstation name, type 0x20 = file server service name
		// Both give us the computer name. Prefer type 0x00.
		if nameType == 0x00 {
			workstation = name
			break
		}
		if nameType == 0x20 && workstation == "" {
			workstation = name
		}
	}

	return workstation
}
