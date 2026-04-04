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

// ping sends an ICMP echo request and returns latency + whether the host replied.
// Tries privileged raw socket first; falls back to unprivileged UDP (requires
// net.ipv4.ping_group_range sysctl on Linux, or run as root).
func ping(ctx context.Context, ip net.IP, timeout time.Duration) (time.Duration, bool) {
	network := "ip4:icmp"
	conn, err := icmp.ListenPacket(network, "0.0.0.0")
	if err != nil {
		network = "udp4"
		conn, err = icmp.ListenPacket(network, "0.0.0.0")
		if err != nil {
			return 0, false
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
		return 0, false
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

	start := time.Now()
	if _, err := conn.WriteTo(b, dst); err != nil {
		return 0, false
	}

	rb := make([]byte, 1500)
	for {
		n, peer, err := conn.ReadFrom(rb)
		if err != nil {
			return 0, false
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
			return time.Since(start), true
		}
	}
}
