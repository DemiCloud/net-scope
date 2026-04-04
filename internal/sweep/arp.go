package sweep

import (
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/mdlayher/arp"
)

// batchARP sends ARP requests for all IPs on the given interface and returns
// a map of IP string → MAC. Uses a single socket: one goroutine sends all
// requests, another reads all replies until the deadline.
func batchARP(iface *net.Interface, ips []net.IP, timeout time.Duration) map[string]net.HardwareAddr {
	client, err := arp.Dial(iface)
	if err != nil {
		return nil
	}
	defer client.Close()

	macs := make(map[string]net.HardwareAddr)
	var mu sync.Mutex
	done := make(chan struct{})

	// Reader goroutine — collects replies until deadline.
	go func() {
		defer close(done)
		client.SetReadDeadline(time.Now().Add(timeout))
		for {
			pkt, _, err := client.Read()
			if err != nil {
				return
			}
			if pkt.Operation == arp.OperationReply {
				mac := make(net.HardwareAddr, len(pkt.SenderHardwareAddr))
				copy(mac, pkt.SenderHardwareAddr)
				mu.Lock()
				macs[pkt.SenderIP.String()] = mac
				mu.Unlock()
			}
		}
	}()

	// Send requests for every IP.
	client.SetWriteDeadline(time.Now().Add(timeout / 2))
	for _, ip := range ips {
		ip4 := ip.To4()
		if ip4 == nil {
			continue
		}
		addr, ok := netip.AddrFromSlice(ip4)
		if !ok {
			continue
		}
		_ = client.Request(addr.Unmap())
	}

	<-done
	return macs
}
