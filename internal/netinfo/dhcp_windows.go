//go:build windows

package netinfo

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"syscall"
	"time"
	"unsafe"
)

// ---------------------------------------------------------------------------
// DHCPEvent — one observed DHCP message on the wire
// ---------------------------------------------------------------------------

// DHCPMsgType mirrors RFC 2132 option 53 values.
type DHCPMsgType uint8

const (
	DHCPDiscover DHCPMsgType = 1
	DHCPOffer    DHCPMsgType = 2
	DHCPRequest  DHCPMsgType = 3
	DHCPDecline  DHCPMsgType = 4
	DHCPAck      DHCPMsgType = 5
	DHCPNak      DHCPMsgType = 6
	DHCPRelease  DHCPMsgType = 7
	DHCPInform   DHCPMsgType = 8
)

func (t DHCPMsgType) String() string {
	switch t {
	case DHCPDiscover:
		return "DISCOVER"
	case DHCPOffer:
		return "OFFER"
	case DHCPRequest:
		return "REQUEST"
	case DHCPDecline:
		return "DECLINE"
	case DHCPAck:
		return "ACK"
	case DHCPNak:
		return "NAK"
	case DHCPRelease:
		return "RELEASE"
	case DHCPInform:
		return "INFORM"
	default:
		return fmt.Sprintf("TYPE(%d)", uint8(t))
	}
}

// DHCPEvent describes one DHCP packet observed passively on the wire.
type DHCPEvent struct {
	Time      time.Time   `json:"time"`
	Type      DHCPMsgType `json:"type"`
	XID       uint32      `json:"xid"`        // transaction ID (links request → reply)
	ClientMAC string      `json:"client_mac"` // chaddr field (6-byte MAC as string)
	ClientIP  string      `json:"client_ip"`  // ciaddr (already has a lease) or 0.0.0.0
	OfferedIP string      `json:"offered_ip"` // yiaddr (address offered/acked by server)
	ServerIP  string      `json:"server_ip"`  // option 54 (DHCP Server Identifier)
	Hostname  string      `json:"hostname"`   // option 12 (Client Hostname)
	RequestedIP string    `json:"requested_ip"` // option 50 (Requested IP Address)
}

// ---------------------------------------------------------------------------
// Raw capture via SIO_RCVALL promiscuous socket (requires elevation)
// ---------------------------------------------------------------------------

const (
	sioRcvall     = syscall.IOC_IN | syscall.IOC_VENDOR | 1 // 0x98000001
	rcvallOn      = uint32(1)
	ipHeaderMinLen = 20
	udpHeaderLen   = 8
	dhcpBootpPort  = 67 // server port; clients send to 67, receive from 67
	dhcpClientPort = 68
	dhcpMinLen     = 236 // minimum BOOTP/DHCP payload (without options)
	dhcpMagic      = 0x63825363 // RFC 2131 magic cookie
)

// ListenDHCP opens a promiscuous raw IP socket on the first non-loopback
// IPv4 interface and streams DHCPEvents to out until ctx is cancelled.
// Returns an error immediately if the socket cannot be opened (not elevated,
// or no suitable interface).
func ListenDHCP(ctx context.Context, out chan<- DHCPEvent) error {
	// Pick the local IPv4 address to bind the raw socket to.
	bindAddr, err := findBindAddr()
	if err != nil {
		return fmt.Errorf("dhcp listen: %w", err)
	}

	// Create raw IPv4 socket.
	s, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_IP)
	if err != nil {
		return fmt.Errorf("dhcp socket: %w", err)
	}

	sa := &syscall.SockaddrInet4{Port: 0}
	copy(sa.Addr[:], bindAddr.To4())
	if err := syscall.Bind(s, sa); err != nil {
		syscall.Closesocket(s)
		return fmt.Errorf("dhcp bind: %w", err)
	}

	// Enable promiscuous mode: receive all IP packets on this interface.
	flag := rcvallOn
	size := uint32(unsafe.Sizeof(flag))
	var returned uint32
	if err := syscall.WSAIoctl(s,
		sioRcvall,
		(*byte)(unsafe.Pointer(&flag)), size,
		nil, 0,
		&returned, nil, 0,
	); err != nil {
		syscall.Closesocket(s)
		return fmt.Errorf("dhcp SIO_RCVALL: %w", err)
	}

	go func() {
		defer syscall.Closesocket(s)
		buf := make([]byte, 65535)
		for {
			if ctx.Err() != nil {
				return
			}
			n, _, err := syscall.Recvfrom(s, buf, 0)
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				continue
			}
			if evt, ok := parseDHCPPacket(buf[:n]); ok {
				select {
				case out <- evt:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	return nil
}

// findBindAddr returns the first non-loopback, non-link-local private IPv4
// address to bind the raw socket to.
func findBindAddr() (net.IP, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := iface.Addrs()
		for _, a := range addrs {
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			ip4 := ip.To4()
			if ip4 == nil {
				continue
			}
			if isPrivateIP(ip4) {
				return ip4, nil
			}
		}
	}
	return nil, fmt.Errorf("no suitable IPv4 interface found")
}

// ---------------------------------------------------------------------------
// DHCP packet parser
// ---------------------------------------------------------------------------

// parseDHCPPacket extracts a DHCPEvent from a raw IP packet.
// Returns (event, true) if the packet is a valid DHCP message.
func parseDHCPPacket(pkt []byte) (DHCPEvent, bool) {
	// Parse IP header.
	if len(pkt) < ipHeaderMinLen {
		return DHCPEvent{}, false
	}
	ihl := int(pkt[0]&0x0F) * 4
	if ihl < ipHeaderMinLen || len(pkt) < ihl+udpHeaderLen {
		return DHCPEvent{}, false
	}
	proto := pkt[9]
	if proto != syscall.IPPROTO_UDP {
		return DHCPEvent{}, false
	}

	// Parse UDP header.
	udp := pkt[ihl:]
	srcPort := binary.BigEndian.Uint16(udp[0:2])
	dstPort := binary.BigEndian.Uint16(udp[2:4])
	if !isDHCPPort(srcPort, dstPort) {
		return DHCPEvent{}, false
	}

	payload := udp[udpHeaderLen:]
	if len(payload) < dhcpMinLen {
		return DHCPEvent{}, false
	}

	// BOOTP/DHCP fixed fields:
	//  0     op (1=request/client, 2=reply/server)
	//  1     htype
	//  2     hlen
	//  3     hops
	//  4-7   xid
	//  8-9   secs
	// 10-11  flags
	// 12-15  ciaddr
	// 16-19  yiaddr
	// 20-23  siaddr
	// 24-27  giaddr
	// 28-43  chaddr (16 bytes, only first 6 used for Ethernet)
	// 44-107 sname
	// 108-235 file
	// 236+   options (magic cookie + TLV)

	xid := binary.BigEndian.Uint32(payload[4:8])
	ciaddr := net.IP(payload[12:16]).String()
	yiaddr := net.IP(payload[16:20]).String()
	hlen := payload[2]
	if hlen > 16 {
		hlen = 16
	}
	mac := net.HardwareAddr(payload[28 : 28+hlen]).String()

	// Check magic cookie.
	if len(payload) < 240 {
		return DHCPEvent{}, false
	}
	if binary.BigEndian.Uint32(payload[236:240]) != dhcpMagic {
		return DHCPEvent{}, false
	}

	// Parse options TLV.
	var (
		msgType     DHCPMsgType
		serverID    string
		hostname    string
		requestedIP string
	)
	opts := payload[240:]
	for i := 0; i < len(opts); {
		code := opts[i]
		if code == 255 { // END
			break
		}
		if code == 0 { // PAD
			i++
			continue
		}
		if i+1 >= len(opts) {
			break
		}
		length := int(opts[i+1])
		if i+2+length > len(opts) {
			break
		}
		val := opts[i+2 : i+2+length]
		switch code {
		case 53: // DHCP Message Type
			if length >= 1 {
				msgType = DHCPMsgType(val[0])
			}
		case 54: // Server Identifier
			if length == 4 {
				serverID = net.IP(val).String()
			}
		case 12: // Host Name
			hostname = string(val)
		case 50: // Requested IP Address
			if length == 4 {
				requestedIP = net.IP(val).String()
			}
		}
		i += 2 + length
	}

	if msgType == 0 {
		return DHCPEvent{}, false // not a DHCP packet (plain BOOTP)
	}

	zero := "0.0.0.0"
	if yiaddr == zero {
		yiaddr = ""
	}
	if ciaddr == zero {
		ciaddr = ""
	}

	return DHCPEvent{
		Time:        time.Now(),
		Type:        msgType,
		XID:         xid,
		ClientMAC:   mac,
		ClientIP:    ciaddr,
		OfferedIP:   yiaddr,
		ServerIP:    serverID,
		Hostname:    hostname,
		RequestedIP: requestedIP,
	}, true
}

func isDHCPPort(src, dst uint16) bool {
	return (src == dhcpClientPort && dst == dhcpBootpPort) ||
		(src == dhcpBootpPort && dst == dhcpClientPort)
}
