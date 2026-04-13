package scan

import (
	"fmt"
	"net"
)

// SendWakeOnLAN sends a Wake-on-LAN magic packet for the given MAC address to
// the specified broadcast address on UDP port 9.
//
// The magic packet is 102 bytes: 6 × 0xFF followed by 16 repetitions of the
// 6-byte target MAC address.
func SendWakeOnLAN(mac net.HardwareAddr, broadcast string) error {
	if len(mac) != 6 {
		return fmt.Errorf("wake-on-lan: MAC must be 6 bytes, got %d", len(mac))
	}

	// Build the 102-byte magic packet.
	var pkt [102]byte
	for i := 0; i < 6; i++ {
		pkt[i] = 0xFF
	}
	for i := 1; i <= 16; i++ {
		copy(pkt[i*6:], mac)
	}

	addr := &net.UDPAddr{
		IP:   net.ParseIP(broadcast),
		Port: 9,
	}
	if addr.IP == nil {
		// Fall back to limited broadcast if the address string is empty or unparseable.
		addr.IP = net.IPv4(255, 255, 255, 255)
	}

	conn, err := net.DialUDP("udp4", nil, addr)
	if err != nil {
		return fmt.Errorf("wake-on-lan: dial: %w", err)
	}
	defer conn.Close()

	if _, err := conn.Write(pkt[:]); err != nil {
		return fmt.Errorf("wake-on-lan: write: %w", err)
	}
	return nil
}
