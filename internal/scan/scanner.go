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
//  2. Batch ARP determines initial live hosts and their MACs
//  3. Phase 1 – liveness sweep: ICMP + TCP probe every host in parallel;
//     alive hosts emit a partial Result (Partial: true) immediately for
//     fast front-end feedback; dead hosts are emitted right away too
//  4. Phase 2 – deep inspection: only confirmed-alive hosts are probed for
//     DNS, open ports, SNMP, NetBIOS, banners, and TCP stack fingerprint
//  5. Broadcast data is merged into full results
//  6. Hosts seen only via broadcast are emitted at the end
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

	// --- 4. Phase 1: liveness sweep ---
	// All hosts are probed concurrently. Alive hosts emit a partial Result
	// immediately so the front-end can begin displaying them without waiting
	// for the slower deep-inspection phase. Dead hosts are also streamed now.
	sem := make(chan struct{}, s.Config.Concurrency)
	var phase1WG sync.WaitGroup
	var aliveMu sync.Mutex
	alivePartials := make([]Result, 0, 16)

	for _, host := range hosts {
		if ctx.Err() != nil {
			break
		}
		sem <- struct{}{}
		phase1WG.Add(1)
		go func(ip net.IP) {
			defer phase1WG.Done()
			defer func() { <-sem }()
			defer func() { _ = recover() }()

			r := s.liveCheck(ctx, ip, macMap, dial)

			if r.Alive {
				r.Partial = true
				// Emit partial result immediately — front-end can show the host now.
				select {
				case out <- r:
				case <-ctx.Done():
				}
				aliveMu.Lock()
				alivePartials = append(alivePartials, r)
				aliveMu.Unlock()
			} else {
				select {
				case out <- r:
				case <-ctx.Done():
				}
			}
		}(host)
	}
	phase1WG.Wait()

	// --- 5. Phase 2: deep inspection of alive hosts ---
	// Only hosts that responded to liveness probes reach this stage.
	// Results are buffered when the broadcast listener is still running so that
	// mDNS/SSDP service data can be merged before OS guessing and emission.
	var phase2WG sync.WaitGroup
	var deepMu sync.Mutex
	pendingResults := make([]Result, 0, len(alivePartials))

	for _, partial := range alivePartials {
		if ctx.Err() != nil {
			break
		}
		sem <- struct{}{}
		phase2WG.Add(1)
		go func(pr Result) {
			defer phase2WG.Done()
			defer func() { <-sem }()
			defer func() { _ = recover() }()

			r := s.deepProbe(ctx, pr, dial)

			if broadcastDone == nil {
				r.OS, r.OSConfidence = guessOS(r.TTL, r.Banner, r.Services, r.SNMP, r.Vendor, r.SYNProbe)
				select {
				case out <- r:
				case <-ctx.Done():
				}
				return
			}
			deepMu.Lock()
			pendingResults = append(pendingResults, r)
			deepMu.Unlock()
		}(partial)
	}
	phase2WG.Wait()

	// --- 6. Wait for broadcast listener, then emit buffered deep results ---
	// Only reached when BroadcastListen > 0 (broadcastDone is non-nil).
	// When BroadcastListen == 0 all results were already streamed above.
	if broadcastDone == nil {
		// Nothing buffered — fall through to emit broadcast-only hosts below.
	} else {
		<-broadcastDone

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

// liveCheck determines whether ip is reachable using ARP, ICMP echo, and a
// quick TCP connect fallback. It returns a partial Result: Alive, IP, MAC,
// Vendor, Latency and TTL may be set, but DNS, open ports, SNMP and banners
// are not populated. Pass the result to deepProbe for full inspection.
//
// Liveness order:
//  1. ARP (pre-populated macMap — fastest, no I/O here)
//  2. ICMP echo (skipped in proxy mode or when PingFirst is false)
//  3. TCP connect on a small set of common ports (works through SOCKS proxy)
func (s *Scanner) liveCheck(ctx context.Context, ip net.IP, macMap map[string]net.HardwareAddr, dial DialFunc) Result {
	r := Result{IP: ip}

	// 1. ARP result → alive + MAC + vendor (no I/O; macMap was pre-populated).
	if mac, ok := macMap[ip.String()]; ok {
		r.Alive = true
		r.MAC = mac
		r.Vendor = lookupVendor(mac)
	}

	// 2. ICMP (skipped in proxy mode or when PingFirst is off).
	if dial == nil && s.Config.PingFirst && !s.Config.TCPFirst {
		if !r.Alive {
			atomic.AddInt64(&s.Stats.PacketsSent, 1)
			latency, ttl, alive := ping(ctx, ip, s.Config.Timeout)
			if alive {
				atomic.AddInt64(&s.Stats.RepliesReceived, 1)
				atomic.AddInt64(&s.Stats.LatencySum, latency.Nanoseconds())
				r.Alive = true
				r.Latency = latency
				r.TTL = ttl
				// ICMP causes the kernel to ARP; read cache to fill the MAC.
				if r.MAC == nil {
					if mac := lookupARPCache(ip); mac != nil {
						r.MAC = mac
						r.Vendor = lookupVendor(mac)
					}
				}
			} else {
				atomic.AddInt64(&s.Stats.Timeouts, 1)
			}
		} else if r.Latency == 0 {
			// Already live via ARP — ping just for latency + TTL.
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

	// 3. TCP liveness fallback — a quick parallel probe on a small set of
	// commonly-open ports. Stops as soon as any one responds. Works through
	// SOCKS proxy. The full port enumeration runs later in deepProbe.
	if !r.Alive {
		livePorts := []int{80, 443, 22, 3389, 8080}
		open := scanPorts(ctx, ip, livePorts, s.Config.Timeout, dial)
		if len(open) > 0 {
			r.Alive = true
			if r.MAC == nil && dial == nil {
				if mac := lookupARPCache(ip); mac != nil {
					r.MAC = mac
					r.Vendor = lookupVendor(mac)
				}
			}
		}
	}

	return r
}

// deepProbe performs full inspection of a confirmed-alive host. It takes the
// partial Result from liveCheck as a starting point and adds DNS, open ports,
// SNMP, NetBIOS, service banners, and TCP stack fingerprint (SYN probe).
func (s *Scanner) deepProbe(ctx context.Context, r Result, dial DialFunc) Result {
	r.Partial = false

	// DNS, port scan, SNMP and NetBIOS run in parallel.
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		r.Hostname = reverseDNS(r.IP, s.Config.Timeout)
		if r.Hostname == "" {
			atomic.AddInt64(&s.Stats.DNSFailures, 1)
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		if len(s.Config.Ports) > 0 {
			r.OpenPorts = scanPorts(ctx, r.IP, s.Config.Ports, s.Config.Timeout, dial)
		}
	}()

	if s.Config.SNMPCommunity != "" && dial == nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r.SNMP = probeSNMP(ctx, r.IP, s.Config.SNMPCommunity, s.Config.Timeout)
		}()
	}

	if s.Config.NetBIOS && dial == nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r.NetBIOS = ProbeNetBIOS(r.IP, s.Config.Timeout)
		}()
	}

	wg.Wait()

	// Banner grab and SYN probe run after port scan.
	// SYN probe does not require a port from the scan list: we try a small set
	// of commonly-open ports so we still get TCP stack data for hosts that
	// expose no ports from the configured scan range.
	if dial == nil {
		synPort := 0
		if len(r.OpenPorts) > 0 {
			synPort = r.OpenPorts[0]
		} else {
			for _, p := range []int{443, 80, 22, 8080, 8443} {
				if probeTCPOpen(ctx, r.IP, p, s.Config.Timeout) {
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
					r.Banner = grabBanners(ctx, r.IP, r.OpenPorts, s.Config.Timeout, dial)
				}()
			}
			postWg.Add(1)
			go func() {
				defer postWg.Done()
				r.SYNProbe = probeSYN(ctx, r.IP, synPort, s.Config.Timeout)
			}()
			postWg.Wait()
		} else if s.Config.BannerGrab && len(r.OpenPorts) > 0 {
			r.Banner = grabBanners(ctx, r.IP, r.OpenPorts, s.Config.Timeout, dial)
		}
	} else if s.Config.BannerGrab && len(r.OpenPorts) > 0 {
		r.Banner = grabBanners(ctx, r.IP, r.OpenPorts, s.Config.Timeout, dial)
	}

	return r
}
