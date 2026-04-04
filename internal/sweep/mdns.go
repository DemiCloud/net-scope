package sweep

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/grandcat/zeroconf"
)

// Common mDNS service types to browse. Covers most LAN devices.
var mdnsServiceTypes = []string{
	"_http._tcp",        // generic web UI (routers, NAS, printers, cameras)
	"_https._tcp",       // HTTPS web UI
	"_ssh._tcp",         // SSH servers
	"_workstation._tcp", // Avahi Linux host announcements
	"_device-info._tcp", // Apple device type records
	"_googlecast._tcp",  // Chromecast / Google TV
	"_airplay._tcp",     // Apple AirPlay
	"_raop._tcp",        // AirPlay audio
	"_printer._tcp",     // printers
	"_ipp._tcp",         // IPP printers
	"_smb._tcp",         // Samba shares
	"_afp._tcp",         // Apple Filing Protocol (NAS, macOS)
	"_nfs._tcp",         // NFS shares
	"_hap._tcp",         // HomeKit accessories
}

// discoverMDNS browses common mDNS service types and returns a map of
// IPv4 string → []ServiceInfo for the duration of timeout.
func discoverMDNS(ctx context.Context, timeout time.Duration) map[string][]ServiceInfo {
	results := make(map[string][]ServiceInfo)
	var mu sync.Mutex
	var wg sync.WaitGroup

	scanCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	for _, svcType := range mdnsServiceTypes {
		wg.Add(1)
		go func(st string) {
			defer wg.Done()
			browseMDNS(scanCtx, st, func(ip net.IP, svc ServiceInfo) {
				key := ip.String()
				mu.Lock()
				results[key] = append(results[key], svc)
				mu.Unlock()
			})
		}(svcType)
	}

	wg.Wait()
	return results
}

func browseMDNS(ctx context.Context, serviceType string, cb func(net.IP, ServiceInfo)) {
	resolver, err := zeroconf.NewResolver(nil)
	if err != nil {
		return
	}

	entries := make(chan *zeroconf.ServiceEntry)
	go func() {
		_ = resolver.Browse(ctx, serviceType, "local.", entries)
	}()

	seen := make(map[string]bool)
	for {
		select {
		case entry, ok := <-entries:
			if !ok {
				return
			}
			for _, ip := range entry.AddrIPv4 {
				key := ip.String() + entry.Instance
				if seen[key] {
					continue
				}
				seen[key] = true
				cb(ip, ServiceInfo{
					Source:  "mdns",
					Name:    entry.Instance,
					Type:    entry.Service,
					Details: entry.Text,
				})
			}
		case <-ctx.Done():
			return
		}
	}
}
