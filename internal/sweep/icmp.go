package sweep

import (
	"context"
	"math/rand"
	"net"
	"os"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

const icmpv4Proto = 1

// ping sends an ICMP echo request and returns (latency, ttl, alive).
// ttl is 0 when using the unprivileged UDP fallback (TTL not accessible).
// Tries privileged raw socket first; falls back to unprivileged UDP (requires
// net.ipv4.ping_group_range sysctl on Linux, or run as root).
func ping(ctx context.Context, ip net.IP, timeout time.Duration) (time.Duration, uint8, bool) {
	network := "ip4:icmp"
	conn, err := icmp.ListenPacket(network, "0.0.0.0")
	if err != nil {
		network = "udp4"
		conn, err = icmp.ListenPacket(network, "0.0.0.0")
		if err != nil {
			return 0, 0, false
		}
	}
	defer conn.Close()

	id := os.Getpid() & 0xffff
	seq := rand.Intn(0xffff) + 1

	msg := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:   id,
			Seq:  seq,
			Data: []byte("net-sweep"),
		},
	}
	b, err := msg.Marshal(nil)
	if err != nil {
		return 0, 0, false
	}

	deadline := time.Now().Add(timeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	conn.SetDeadline(deadline)

	var dst net.Addr
	if network == "udp4" {
		dst = &net.UDPAddr{IP: ip}
	} else {
		dst = &net.IPAddr{IP: ip}
	}

	// For the raw ip4:icmp socket, enable TTL reading via IPv4 control messages.
	var p4 *ipv4.PacketConn
	if network == "ip4:icmp" {
		p4 = ipv4.NewPacketConn(conn)
		_ = p4.SetControlMessage(ipv4.FlagTTL, true)
	}

	start := time.Now()
	if _, err := conn.WriteTo(b, dst); err != nil {
		return 0, 0, false
	}

	rb := make([]byte, 1500)
	for {
		var (
			n    int
			peer net.Addr
			ttl  uint8
		)

		if p4 != nil {
			var cm *ipv4.ControlMessage
			n, cm, peer, err = p4.ReadFrom(rb)
			if err != nil {
				return 0, 0, false
			}
			if cm != nil {
				ttl = uint8(cm.TTL)
			}
		} else {
			n, peer, err = conn.ReadFrom(rb)
			if err != nil {
				return 0, 0, false
			}
		}

		rm, err := icmp.ParseMessage(icmpv4Proto, rb[:n])
		if err != nil {
			continue
		}
		if rm.Type != ipv4.ICMPTypeEchoReply {
			continue
		}
		echo, ok := rm.Body.(*icmp.Echo)
		if !ok || echo.ID != id || echo.Seq != seq {
			continue
		}

		var peerIP net.IP
		switch a := peer.(type) {
		case *net.IPAddr:
			peerIP = a.IP
		case *net.UDPAddr:
			peerIP = a.IP
		}
		if peerIP != nil && peerIP.Equal(ip) {
			return time.Since(start), ttl, true
		}
	}
}

