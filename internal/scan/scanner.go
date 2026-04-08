package scan

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/proxy"
)

// Scanner orchestrates host discovery and port scanning across a target range.
type Scanner struct {
	Config Config
	// Stats accumulates probe counters during the scan; safe to read after
	// the result channel is closed.
	Stats ScanStats
}

// ScanStats tracks diagnostic counters for a single scan run.
type ScanStats struct {
	PacketsSent     int64
	RepliesReceived int64
	Timeouts        int64
	LatencySum      int64 // nanoseconds, divide by RepliesReceived for average
	// ARPAnomalies counts cases where the same IP appeared with different MACs
	// in the ARP table during a single scan (possible duplicate or spoofing).
	ARPAnomalies int64
	// DNSFailures counts reverse-DNS lookup failures.
	DNSFailures int64
}

// AvgLatencyMS returns the average probe round-trip in milliseconds, or 0.
func (s *ScanStats) AvgLatencyMS() float64 {
	if s.RepliesReceived == 0 {
		return 0
	}
	return float64(s.LatencySum) / float64(s.RepliesReceived) / 1e6
}

// Config holds tunable parameters for a scan.
type Config struct {
	Timeout         time.Duration
	Concurrency     int
	Ports           []int
	PingFirst       bool   // fall back to ICMP if ARP misses a host
	SNMPCommunity   string // "" disables SNMP
	Interface       string // "" = auto-detect from routing table
	BroadcastListen time.Duration // how long to listen for mDNS/SSDP; 0 = disabled
	BannerGrab      bool          // grab service banners from open ports
	NetBIOS         bool          // query NetBIOS names (UDP 137)
	TCPFirst        bool          // use TCP connect as liveness probe (no raw socket needed)
	// SOCKSProxy is the address of a SOCKS5 proxy (e.g. "127.0.0.1:1080").
	// When set, all TCP connections are routed through the proxy and
	// ARP, ICMP, mDNS, SSDP, WSD, NetBIOS, and SNMP are disabled.
	SOCKSProxy string
}

// DialFunc is a context-aware TCP dial function. nil means use the system default.
type DialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// MakeDialFunc returns a DialFunc that routes connections through the SOCKS5
// proxy at addr, or nil (direct) when addr is empty.
func MakeDialFunc(addr string) (DialFunc, error) {
	if addr == "" {
		return nil, nil
	}
	d, err := proxy.SOCKS5("tcp", addr, nil, proxy.Direct)
	if err != nil {
		return nil, fmt.Errorf("socks5 proxy %q: %w", addr, err)
	}
	if cd, ok := d.(proxy.ContextDialer); ok {
		return cd.DialContext, nil
	}
	return func(ctx context.Context, network, a string) (net.Conn, error) {
		return d.Dial(network, a)
	}, nil
}

// dialOrDirect returns dial if non-nil, otherwise returns a default net.Dialer.DialContext.
func dialOrDirect(dial DialFunc) DialFunc {
	if dial != nil {
		return dial
	}
	return (&net.Dialer{}).DialContext
}

// DefaultConfig returns sensible defaults for a LAN scan.
func DefaultConfig() Config {
	return Config{
		Timeout:         1 * time.Second,
		Concurrency:     256,
		Ports:           []int{22, 80, 443, 445, 3389, 8080, 8443},
		PingFirst:       true,
		SNMPCommunity:   "public",
		BroadcastListen: 5 * time.Second,
		BannerGrab:      true,
		NetBIOS:         true,
	}
}

// NewScanner creates a Scanner with the given config.
func NewScanner(cfg Config) *Scanner {
	return &Scanner{Config: cfg}
}

// Scan runs discovery over the provided CIDR or single IP, streaming Result
// values to the returned channel. The channel is closed when the scan
// completes or the context is cancelled.
//
// Scan flow:
//  1. Broadcast discovery (mDNS + SSDP) starts concurrently
//  2. Batch ARP determines live hosts and their MACs
//  3. Per-host probing (ICMP fallback, ports, SNMP, DNS) runs in parallel
//  4. Broadcast data is merged into each host result
//  5. Hosts seen only via broadcast are emitted at the end
func (s *Scanner) Scan(ctx context.Context, target string) (<-chan Result, error) {
	if s.Config.SOCKSProxy != "" {
		if _, err := MakeDialFunc(s.Config.SOCKSProxy); err != nil {
			return nil, err
		}
	}
	hosts, err := expandTarget(target)
	if err != nil {
		return nil, err
	}

	results := make(chan Result, len(hosts)+32)

	go func() {
		defer close(results)
		defer func() {
			// Recover panics (e.g. permission denied on raw socket) so the
			// channel is always closed and the caller's range loop terminates.
			_ = recover()
		}()
		s.runScan(ctx, hosts, results)
	}()

	return results, nil
}

func (s *Scanner) runScan(ctx context.Context, hosts []net.IP, out chan<- Result) {
	// --- Proxy dialer (nil = direct connections) ---
	dial, _ := MakeDialFunc(s.Config.SOCKSProxy)

	// --- 1. Network interface ---
	var iface *net.Interface
	if s.Config.Interface != "" {
		var err error
		iface, err = net.InterfaceByName(s.Config.Interface)
		if err != nil {
			// Named interface not found — proceed without ARP.
			iface = nil
		}
	} else if len(hosts) > 0 {
		iface, _ = findInterface(hosts[0])
	}

	// --- 2. Broadcast discovery (runs concurrently with ARP + host sweep) ---
	// Skipped in proxy mode: mDNS/SSDP are link-local multicast, not routable
	// through a SOCKS tunnel.
	broadcastMap := make(map[string][]ServiceInfo)
	var broadcastMu sync.Mutex
	var broadcastDone chan struct{}

	if s.Config.BroadcastListen > 0 && dial == nil {
		broadcastDone = make(chan struct{})
		go func() {
			defer close(broadcastDone)
			defer func() { _ = recover() }()
			bctx, cancel := context.WithTimeout(ctx, s.Config.BroadcastListen)
			defer cancel()

			var wg sync.WaitGroup
			wg.Add(2)
			go func() {
				defer wg.Done()
				defer func() { _ = recover() }()
				for ip, svcs := range discoverMDNS(bctx, s.Config.BroadcastListen) {
					broadcastMu.Lock()
					broadcastMap[ip] = append(broadcastMap[ip], svcs...)
					broadcastMu.Unlock()
				}
			}()
			go func() {
				defer wg.Done()
				defer func() { _ = recover() }()
				for ip, svcs := range discoverSSDP(bctx, s.Config.BroadcastListen) {
					broadcastMu.Lock()
					broadcastMap[ip] = append(broadcastMap[ip], svcs...)
					broadcastMu.Unlock()
				}
			}()
			wg.Wait()
		}()
	}

	// --- 3. Batch ARP (fast LAN MAC discovery) ---
	// Wrapped in its own recover: mdlayher/arp panics on platforms without
	// raw Ethernet support (e.g. Windows without npcap). A nil map is safe —
	// all hosts fall through to ICMP / TCP liveness probes.
	// Skipped in proxy mode: ARP is a Layer-2 protocol, not routable through SOCKS.
	var macMap map[string]net.HardwareAddr
	if iface != nil && dial == nil {
		func() {
			defer func() { _ = recover() }()
			macMap = batchARP(iface, hosts, s.Config.Timeout*2)
		}()
		// Detect ARP anomalies: compare with kernel ARP cache.
		for ipStr, batchMAC := range macMap {
			ip := net.ParseIP(ipStr)
			if ip == nil {
				continue
			}
			cacheMAC := lookupARPCache(ip)
			if cacheMAC != nil && cacheMAC.String() != batchMAC.String() {
				atomic.AddInt64(&s.Stats.ARPAnomalies, 1)
			}
		}
	}

	// --- 4. Per-host probing ---
	sem := make(chan struct{}, s.Config.Concurrency)
	var wg sync.WaitGroup
	var resultsMu sync.Mutex
	pendingResults := make([]Result, 0, len(hosts))

	for _, host := range hosts {
		if ctx.Err() != nil {
			break
		}
		sem <- struct{}{}
		wg.Add(1)
		go func(ip net.IP) {
			defer wg.Done()
			defer func() { <-sem }()
			defer func() { _ = recover() }() // raw-socket panics must not kill the process

			r := s.probeHost(ctx, ip, macMap, dial)

			// Stash result; services and OS are finalised after broadcastDone.
			resultsMu.Lock()
			pendingResults = append(pendingResults, r)
			resultsMu.Unlock()
		}(host)
	}
	wg.Wait()

	// --- 5. Wait for broadcast listener, then emit all host results ---
	// Waiting here ensures mDNS/SSDP records collected during host probing
	// are available when guessOS runs, even for fast-responding hosts.
	if broadcastDone != nil {
		<-broadcastDone
	}

	broadcastMu.Lock()
	for i := range pendingResults {
		r := &pendingResults[i]
		if svcs := broadcastMap[r.IP.String()]; len(svcs) > 0 {
			r.Services = svcs
		}
		r.OS, r.OSConfidence = guessOS(r.TTL, r.Banner, r.Services, r.SNMP, r.Vendor, r.SYNProbe)
	}
	broadcastMu.Unlock()

	for _, r := range pendingResults {
		select {
		case out <- r:
		case <-ctx.Done():
			return
		}
	}

	swept := make(map[string]bool, len(hosts))
	for _, h := range hosts {
		swept[h.String()] = true
	}

	broadcastMu.Lock()
	defer broadcastMu.Unlock()
	for ipStr, svcs := range broadcastMap {
		if swept[ipStr] {
			continue
		}
		ip := net.ParseIP(ipStr)
		if ip == nil {
			continue
		}
		select {
		case out <- Result{IP: ip.To4(), Alive: true, Services: svcs}:
		case <-ctx.Done():
			return
		}
	}
}

// probeHost runs all per-host probes and returns a populated Result.
func (s *Scanner) probeHost(ctx context.Context, ip net.IP, macMap map[string]net.HardwareAddr, dial DialFunc) Result {
	r := Result{IP: ip}

	// ARP result → alive + MAC + vendor
	if mac, ok := macMap[ip.String()]; ok {
		r.Alive = true
		r.MAC = mac
		r.Vendor = lookupVendor(mac)
	}

	// ICMP fallback if ARP missed the host (skipped in proxy mode).
	if dial == nil && !r.Alive && s.Config.PingFirst {
		atomic.AddInt64(&s.Stats.PacketsSent, 1)
		latency, ttl, alive := ping(ctx, ip, s.Config.Timeout)
		if alive {
			atomic.AddInt64(&s.Stats.RepliesReceived, 1)
			atomic.AddInt64(&s.Stats.LatencySum, latency.Nanoseconds())
			r.Alive = true
			r.Latency = latency
			r.TTL = ttl
			// The ICMP probe causes the kernel to ARP for the host, so the
			// neighbor cache is now populated. Read it to fill in the MAC
			// (handles the common case of Windows running without admin where
			// batchARP is unavailable).
			if r.MAC == nil {
				if mac := lookupARPCache(ip); mac != nil {
					r.MAC = mac
					r.Vendor = lookupVendor(mac)
				}
			}
		} else {
			atomic.AddInt64(&s.Stats.Timeouts, 1)
		}
	} else if dial == nil && r.Alive && s.Config.PingFirst {
		// We got MAC via ARP but still want latency + TTL — ping if no latency yet.
		if r.Latency == 0 {
			atomic.AddInt64(&s.Stats.PacketsSent, 1)
			latency, ttl, ok := ping(ctx, ip, s.Config.Timeout)
			if ok {
				atomic.AddInt64(&s.Stats.RepliesReceived, 1)
				atomic.AddInt64(&s.Stats.LatencySum, latency.Nanoseconds())
				r.Latency = latency
				r.TTL = ttl
			} else {
				atomic.AddInt64(&s.Stats.Timeouts, 1)
			}
		}
	}

	// TCP liveness fallback — last resort when ARP/ICMP both failed, or the
	// primary path in proxy mode (where ARP+ICMP are always skipped).
	if !r.Alive && len(s.Config.Ports) > 0 {
		open := scanPorts(ctx, ip, s.Config.Ports, s.Config.Timeout, dial)
		if len(open) > 0 {
			r.Alive = true
			r.OpenPorts = open // already have results — skip the second scan below
			// Try to fill in MAC from kernel ARP cache (populated by TCP SYN).
			if r.MAC == nil {
				if mac := lookupARPCache(ip); mac != nil {
					r.MAC = mac
					r.Vendor = lookupVendor(mac)
				}
			}
		}
	}

	if !r.Alive {
		return r
	}

	// Reverse DNS, ports, SNMP, NetBIOS run in parallel.
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		r.Hostname = reverseDNS(ip, s.Config.Timeout)
		if r.Hostname == "" {
			atomic.AddInt64(&s.Stats.DNSFailures, 1)
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		if len(s.Config.Ports) > 0 && len(r.OpenPorts) == 0 {
			r.OpenPorts = scanPorts(ctx, ip, s.Config.Ports, s.Config.Timeout, dial)
		}
	}()

	if s.Config.SNMPCommunity != "" && dial == nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r.SNMP = probeSNMP(ctx, ip, s.Config.SNMPCommunity, s.Config.Timeout)
		}()
	}

	if s.Config.NetBIOS && dial == nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r.NetBIOS = ProbeNetBIOS(ip, s.Config.Timeout)
		}()
	}

	wg.Wait()

	// Banner grab and SYN probe run after port scan.
	// SYN probe does not require a port from the scan list: we try a small set
	// of commonly-open ports (443, 80, 22) so we still get TCP stack data for
	// hosts that expose no ports from the configured scan range (e.g. Apple TV,
	// smart TVs, IoT devices that only speak non-standard ports).
	if dial == nil {
		synPort := 0
		if len(r.OpenPorts) > 0 {
			synPort = r.OpenPorts[0]
		} else {
			for _, p := range []int{443, 80, 22, 8080, 8443} {
				if probeTCPOpen(ctx, ip, p, s.Config.Timeout) {
					synPort = p
					break
				}
			}
		}
		if synPort > 0 {
			var postWg sync.WaitGroup
			if s.Config.BannerGrab && len(r.OpenPorts) > 0 {
				postWg.Add(1)
				go func() {
					defer postWg.Done()
					r.Banner = grabBanners(ctx, ip, r.OpenPorts, s.Config.Timeout, dial)
				}()
			}
			postWg.Add(1)
			go func() {
				defer postWg.Done()
				r.SYNProbe = probeSYN(ctx, ip, synPort, s.Config.Timeout)
			}()
			postWg.Wait()
		} else if s.Config.BannerGrab && len(r.OpenPorts) > 0 {
			r.Banner = grabBanners(ctx, ip, r.OpenPorts, s.Config.Timeout, dial)
		}
	} else if s.Config.BannerGrab && len(r.OpenPorts) > 0 {
		r.Banner = grabBanners(ctx, ip, r.OpenPorts, s.Config.Timeout, dial)
	}

	return r
}
