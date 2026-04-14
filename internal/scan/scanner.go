package scan

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/proxy"

	"github.com/demicloud/net-scope/internal/netinfo"
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

// ThrottlePreset names control how aggressively the scanner probes the network.
// The zero value ("" or "balanced") is the default.
const (
	ThrottleAggressive = "aggressive" // full concurrency, no rate limit, raw sockets allowed
	ThrottleBalanced   = "balanced"   // capped concurrency, no rate limit (default)
	ThrottlePolite     = "polite"     // low concurrency, rate-limited, jitter, no raw sockets
)

// throttleSettings is the resolved runtime parameters for a ThrottlePreset.
type throttleSettings struct {
	// MaxConcurrency caps the number of in-flight host goroutines.
	// 0 means use Config.Concurrency unchanged.
	MaxConcurrency int
	// MaxRatePerSec is the maximum host probes dispatched per second.
	// 0 means unlimited.
	MaxRatePerSec int
	// JitterMs is the maximum random extra delay (ms) added between host dispatches.
	JitterMs int
	// RandomiseOrder shuffles the host list before scanning.
	RandomiseOrder bool
	// ForceNoRawSockets sets TCPFirst=true, disabling ICMP and ARP.
	ForceNoRawSockets bool
}

// resolveThrottle returns the throttle settings for the given preset string.
// An unrecognised value falls back to balanced.
func resolveThrottle(preset string) throttleSettings {
	switch preset {
	case ThrottleAggressive:
		return throttleSettings{
			MaxConcurrency:    0,
			MaxRatePerSec:     0,
			JitterMs:          0,
			RandomiseOrder:    false,
			ForceNoRawSockets: false,
		}
	case ThrottlePolite:
		return throttleSettings{
			MaxConcurrency:    20,
			MaxRatePerSec:     50,
			JitterMs:          50,
			RandomiseOrder:    true,
			ForceNoRawSockets: true,
		}
	default: // "balanced" or ""
		return throttleSettings{
			MaxConcurrency:    128,
			MaxRatePerSec:     0,
			JitterMs:          0,
			RandomiseOrder:    false,
			ForceNoRawSockets: false,
		}
	}
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
	// ThrottlePreset controls scan aggressiveness. One of ThrottleAggressive,
	// ThrottleBalanced (default), or ThrottlePolite.
	ThrottlePreset string
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
		BroadcastListen: 3 * time.Second,
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
//  3. Per-host goroutine (all hosts concurrently):
//     a. Liveness check (ARP hit, ICMP, TCP fallback) — emits Partial:true immediately
//     b. Deep inspection inline (no phase barrier) — emits final result with
//        whatever broadcast services are already known
//  4. Hosts seen only via broadcast are emitted after the listener finishes
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

	// --- 2. Broadcast discovery (streaming, concurrent with ARP + host sweep) ---
	// Skipped in proxy mode: mDNS/SSDP are link-local multicast, not routable
	// through a SOCKS tunnel.
	//
	// The broadcast callback fires as each device is heard:
	//   • If the IP is in our sweep, services are added to broadcastMap
	//     (deepProbe will merge them on completion).
	//   • If the IP is not in our sweep, a live Result is emitted directly
	//     to out — no waiting until the host sweep finishes.
	broadcastMap := make(map[string][]ServiceInfo)
	var broadcastMu sync.Mutex
	var broadcastDone chan struct{}

	if s.Config.BroadcastListen > 0 && dial == nil {
		broadcastDone = make(chan struct{})

		// sweptSet is read-only after this goroutine starts (populated below),
		// so we build it now before launching the goroutine.
		sweptSet := make(map[string]bool, len(hosts))
		for _, h := range hosts {
			sweptSet[h.String()] = true
		}

		broadcastCB := func(ip net.IP, svc ServiceInfo) {
			ipStr := ip.String()
			broadcastMu.Lock()
			broadcastMap[ipStr] = append(broadcastMap[ipStr], svc)
			isSwept := sweptSet[ipStr]
			broadcastMu.Unlock()

			if !isSwept {
				// Not in our probe sweep — emit immediately as a live host.
				// Multiple services from the same IP will each send an update;
				// the front-end merges by IP (Partial:true updates flow the same way).
				ip4 := ip.To4()
				if ip4 == nil {
					return
				}
				// Build the full services slice seen so far for this IP so the
				// front-end row gets incrementally richer rather than duplicated.
				broadcastMu.Lock()
				svcs := make([]ServiceInfo, len(broadcastMap[ipStr]))
				copy(svcs, broadcastMap[ipStr])
				broadcastMu.Unlock()
				select {
				case out <- Result{IP: ip4, Alive: true, Partial: true, Services: svcs}:
				case <-ctx.Done():
				}
			}
		}

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
				for _, svcType := range mdnsServiceTypes {
					st := svcType
					wg.Add(1)
					go func() {
						defer wg.Done()
						defer func() { _ = recover() }()
						browseMDNS(bctx, st, broadcastCB)
					}()
				}
			}()
			go func() {
				defer wg.Done()
				defer func() { _ = recover() }()
				streamSSDP(bctx, s.Config.BroadcastListen, broadcastCB)
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
			cacheMAC := netinfo.LookupARPCache(ip)
			if cacheMAC != nil && cacheMAC.String() != batchMAC.String() {
				atomic.AddInt64(&s.Stats.ARPAnomalies, 1)
			}
		}
	}

	// --- 4. Per-host probing (liveness + deep inspection, pipelined) ---
	// One goroutine per host handles both phases inline — no barrier between
	// liveness and deep inspection. When a host responds to liveness, its
	// partial Result is emitted immediately; deepProbe then runs without
	// waiting for all other hosts to finish their liveness checks.
	//
	// Broadcast services are merged from whatever has been discovered by the
	// time deepProbe completes. Broadcast runs concurrently, so earlier-
	// finishing hosts get fewer services merged (devices responding fast on
	// mDNS still appear later in the stream as broadcast-only hosts if missed).

	// Apply throttle preset.
	throttle := resolveThrottle(s.Config.ThrottlePreset)
	concurrency := s.Config.Concurrency
	if throttle.MaxConcurrency > 0 && throttle.MaxConcurrency < concurrency {
		concurrency = throttle.MaxConcurrency
	}
	if s.Config.ThrottlePreset == ThrottleAggressive && s.Config.Concurrency > 0 {
		concurrency = s.Config.Concurrency // aggressive: honour config exactly
	}
	if concurrency <= 0 {
		concurrency = 256
	}
	if throttle.ForceNoRawSockets {
		// Polite mode: disable raw-socket operations for this scan run.
		// We shadow the scanner's config locally so the caller's struct is unchanged.
		localCfg := s.Config
		localCfg.TCPFirst = true
		s = &Scanner{Config: localCfg, Stats: s.Stats}
		iface = nil // skip ARP (already ran above, mac map is populated; skip future raw ops)
	}
	if throttle.RandomiseOrder {
		rand.Shuffle(len(hosts), func(i, j int) { hosts[i], hosts[j] = hosts[j], hosts[i] })
	}

	// Optional rate limiter: a ticker that allows MaxRatePerSec dispatches/sec.
	// nil means unlimited.
	var rateTick <-chan time.Time
	var rateTicker *time.Ticker
	if throttle.MaxRatePerSec > 0 {
		rateTicker = time.NewTicker(time.Second / time.Duration(throttle.MaxRatePerSec))
		rateTick = rateTicker.C
		defer rateTicker.Stop()
	}

	sem := make(chan struct{}, concurrency)
	var scanWG sync.WaitGroup

	for _, host := range hosts {
		if ctx.Err() != nil {
			break
		}
		// Rate limiting: wait for a tick before dispatching the next goroutine.
		if rateTick != nil {
			select {
			case <-rateTick:
			case <-ctx.Done():
				break
			}
		}
		// Jitter: randomised extra delay to avoid bursty probing patterns.
		if throttle.JitterMs > 0 {
			delay := time.Duration(rand.Intn(throttle.JitterMs)) * time.Millisecond
			select {
			case <-time.After(delay):
			case <-ctx.Done():
				break
			}
		}
		sem <- struct{}{}
		scanWG.Add(1)
		go func(ip net.IP) {
			defer scanWG.Done()
			defer func() { <-sem }()
			defer func() { _ = recover() }()

			r := s.liveCheck(ctx, ip, macMap, dial)

			if !r.Alive {
				select {
				case out <- r:
				case <-ctx.Done():
				}
				return
			}

			// Emit partial immediately — front-end shows the host while we probe.
			r.Partial = true
			select {
			case out <- r:
			case <-ctx.Done():
				return
			}

			// Deep inspection runs inline — no second-phase barrier.
			r = s.deepProbe(ctx, r, dial)

			// Merge any broadcast services already discovered for this IP.
			broadcastMu.Lock()
			if svcs := broadcastMap[r.IP.String()]; len(svcs) > 0 {
				r.Services = append(r.Services, svcs...)
			}
			broadcastMu.Unlock()

			r.OS, r.OSConfidence = guessOS(r.TTL, r.Banner, r.Services, r.SNMP, r.Vendor, r.SYNProbe)
			select {
			case out <- r:
			case <-ctx.Done():
			}
		}(host)
	}
	scanWG.Wait()
	// The result channel closes as soon as the host sweep completes.
	// Broadcast-only hosts have already been streamed via broadcastCB as they
	// arrived. broadcastDone is not waited on here — the goroutine may still
	// be running, but the caller's range loop will drain any remaining sends
	// before the channel is closed by the deferred close in Scan().
	//
	// Note: if a broadcast-only host arrives after scanWG.Wait() returns but
	// before out is closed, the broadcastCB select will send it or detect
	// ctx.Done — both are safe. The outer goroutine in Scan() does not return
	// until runScan returns, so out is still open here.
	//
	// We do need to wait for broadcastDone before returning so that in-flight
	// broadcastCB calls don't race against out being closed by the deferred
	// close(results) in Scan(). Wait with context awareness.
	if broadcastDone != nil {
		select {
		case <-broadcastDone:
		case <-ctx.Done():
			// Scan cancelled: drain the goroutine on next GC cycle; safe.
		}
	}
}

// firstOpenPort probes all ports concurrently and returns the first one that
// accepts a TCP connection, or 0 if none respond within timeout. Cancels the
// remaining dials as soon as one succeeds, so the worst-case wait is exactly
// one timeout rather than N × timeout when probing sequentially.
func firstOpenPort(ctx context.Context, ip net.IP, ports []int, timeout time.Duration) int {
	ctx2, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	found := make(chan int, 1)
	var once sync.Once
	var wg sync.WaitGroup

	for _, p := range ports {
		wg.Add(1)
		go func(port int) {
			defer wg.Done()
			addr := fmt.Sprintf("%s:%d", ip, port)
			conn, err := (&net.Dialer{}).DialContext(ctx2, "tcp", addr)
			if err == nil {
				conn.Close()
				once.Do(func() {
					found <- port
					cancel() // abort remaining dials immediately
				})
			}
		}(p)
	}

	go func() {
		wg.Wait()
		close(found)
	}()

	port, _ := <-found
	return port
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
					if mac := netinfo.LookupARPCache(ip); mac != nil {
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
				if mac := netinfo.LookupARPCache(ip); mac != nil {
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
		r.Hostname = reverseDNS(ctx, r.IP, s.Config.Timeout)
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
	// Elect a SYN probe port: if we have confirmed open ports use the first;
	// otherwise probe candidates in parallel and take whichever responds first.
	// Parallel probing avoids the sequential worst-case of 5 × timeout when
	// all candidates are filtered (no RST).
	if dial == nil {
		synPort := 0
		if len(r.OpenPorts) > 0 {
			synPort = r.OpenPorts[0]
		} else {
			synPort = firstOpenPort(ctx, r.IP, []int{443, 80, 22, 8080, 8443}, s.Config.Timeout)
		}
		if synPort > 0 {
			var postWg sync.WaitGroup
			if s.Config.BannerGrab && len(r.OpenPorts) > 0 {
				postWg.Add(1)
				go func() {
					defer postWg.Done()
					r.PortServices = grabPortServices(ctx, r.IP, r.OpenPorts, s.Config.Timeout, dial)
					r.Banner = bannerInfoFrom(r.PortServices)
				}()
			}
			postWg.Add(1)
			go func() {
				defer postWg.Done()
				r.SYNProbe = probeSYN(ctx, r.IP, synPort, s.Config.Timeout)
			}()
			postWg.Wait()
		} else if s.Config.BannerGrab && len(r.OpenPorts) > 0 {
			r.PortServices = grabPortServices(ctx, r.IP, r.OpenPorts, s.Config.Timeout, dial)
			r.Banner = bannerInfoFrom(r.PortServices)
		}
	} else if s.Config.BannerGrab && len(r.OpenPorts) > 0 {
		r.PortServices = grabPortServices(ctx, r.IP, r.OpenPorts, s.Config.Timeout, dial)
		r.Banner = bannerInfoFrom(r.PortServices)
	}

	return r
}
