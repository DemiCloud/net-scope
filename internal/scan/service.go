package scan

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// Wire types — GUI ↔ service (newline-delimited JSON over TLS localhost)
// ---------------------------------------------------------------------------

// ServiceCmd is sent by the GUI to the service.
type ServiceCmd struct {
	// Cmd is one of: "scan", "stop", "probe", "dhcp-start", "dhcp-stop",
	// "bcast-start", "bcast-stop", "arp-start", "arp-stop",
	// "arp-snapshot", "arp-delete", "arp-clear",
	// "dns-snapshot", "dns-delete", "dns-clear",
	// "route-snapshot", "route-delete",
	// "netbios", "proxy-test", "oui-update", "shutdown"
	Cmd        string     `json:"cmd"`
	Target     string     `json:"target,omitempty"`
	Config     *Config    `json:"config,omitempty"`
	// ScanID is echoed back in every Result and Done message for this scan.
	// The GUI uses it to discard results from superseded scans.
	ScanID     uint64     `json:"scan_id,omitempty"`
	// Probe is set for the "probe" command.
	Probe      *ProbeSpec `json:"probe,omitempty"`
	// SOCKSProxy is the SOCKS5 address to use for the probe (empty = direct).
	// Also used for "proxy-test".
	SOCKSProxy string     `json:"socks_proxy,omitempty"`
	// BcastListen is the Go duration string for the broadcast window ("bcast-start").
	BcastListen string    `json:"bcast_listen,omitempty"`
	// DataDir is the filesystem path for outputs that need it ("oui-update").
	DataDir     string    `json:"data_dir,omitempty"`
}

// ServiceMsg is sent by the service to the GUI.
type ServiceMsg struct {
	// Ready is sent once after connection is established.
	// Elevated reports whether the service process is running as admin.
	Ready    bool         `json:"ready,omitempty"`
	Elevated bool         `json:"elevated,omitempty"`
	// Result carries a single scanned host; ScanID identifies the scan.
	Result   *Result      `json:"result,omitempty"`
	// Done marks end of a scan; Stats is populated; ScanID identifies the scan.
	Done     bool         `json:"done,omitempty"`
	Stats    *ScanStats   `json:"stats,omitempty"`
	// ScanID is the value from the matching ServiceCmd.ScanID.
	ScanID   uint64       `json:"scan_id,omitempty"`
	// DHCP carries a single passively-observed DHCP packet.
	DHCP     *DHCPEvent   `json:"dhcp,omitempty"`
	// ProbeResult carries the result of a single on-demand host probe.
	ProbeResult *ProbeResult `json:"probe_result,omitempty"`
	// Err carries a human-readable error string.
	Err      string       `json:"err,omitempty"`

	// BcastReady is sent once when the broadcast listener starts (BcastErr
	// is empty on success, non-empty if multicast binding failed).
	BcastReady bool         `json:"bcast_ready,omitempty"`
	BcastErr   string       `json:"bcast_err,omitempty"`
	// BcastSvc carries a single passive-discovery event (mDNS / SSDP / WSD).
	BcastSvc   *ServiceInfo `json:"bcast_svc,omitempty"`
	BcastIP    string       `json:"bcast_ip,omitempty"`

	// ARPEntry carries a single ARP table entry.
	// When ARPSnapshot is true the entry came from an "arp-snapshot" one-shot
	// command; without it the entry came from the continuous "arp-start" poll.
	ARPEntry    *ARPResult `json:"arp_entry,omitempty"`
	ARPSnapshot bool       `json:"arp_snapshot,omitempty"`
	// ARPSnapDone signals the end of an "arp-snapshot" stream.
	ARPSnapDone bool       `json:"arp_snap_done,omitempty"`
	// DNSEntry carries a single DNS resolver cache entry ("dns-snapshot" stream).
	DNSEntry   *DNSCacheEntry `json:"dns_entry,omitempty"`
	// DNSSnapDone signals the end of a "dns-snapshot" stream.
	DNSSnapDone bool          `json:"dns_snap_done,omitempty"`
	// CacheOp carries the result of an "arp-delete", "arp-clear", "dns-delete",
	// "dns-clear", or "route-delete" command.
	CacheOp    *CacheOpResult `json:"cache_op,omitempty"`
	// RouteEntry carries a single routing-table entry ("route-snapshot" stream).
	RouteEntry   *RouteEntry `json:"route_entry,omitempty"`
	// RouteSnapDone signals the end of a "route-snapshot" stream.
	RouteSnapDone bool       `json:"route_snap_done,omitempty"`
	// Netbios carries the result of a NetBIOS name query.
	Netbios    *NetBIOSMsg  `json:"netbios,omitempty"`

	// ProxyOK / ProxyErr carry the result of a "proxy-test" command.
	ProxyOK    bool         `json:"proxy_ok,omitempty"`
	ProxyErr   string       `json:"proxy_err,omitempty"`

	// OUIComplete / OUIErr carry the result of an "oui-update" command.
	OUIComplete bool         `json:"oui_complete,omitempty"`
	OUIErr      string       `json:"oui_err,omitempty"`

	// PTRUpdate carries a background reverse-DNS enrichment for a previously-scanned IP.
	PTRUpdate   *PTRResult   `json:"ptr_update,omitempty"`
	// ResolveResult carries the result of a "resolve" command (forward DNS).
	ResolveResult *ResolveResult `json:"resolve_result,omitempty"`
	// SvcUpdate carries a unified Service with updated evidence. Emitted after
	// every port-probe or broadcast-discovery upsert into the session registry.
	SvcUpdate *Service `json:"svc_update,omitempty"`
	// WorkUpdate carries a host probe state transition (queued → running → done/dead).
	// Emitted by the service throughout a scan so the GUI can display a live queue.
	WorkUpdate *WorkItem `json:"work_update,omitempty"`
	// WorkerStatus carries a named background goroutine state change (started / stopped).
	// Emitted when any long-running service worker (broadcast listener, DHCP capture,
	// ARP poll, PTR resolver, port scanner) starts or stops.
	WorkerStatus *WorkerStatus `json:"worker_status,omitempty"`
}

// ARPResult carries a single ARP table entry streamed from service to GUI.
type ARPResult struct {
	IP      string `json:"ip"`
	MAC     string `json:"mac"`
	Type    string `json:"type,omitempty"`    // "dynamic", "static", "other"; set on arp-snapshot
	IfIndex uint32 `json:"if_index,omitempty"` // interface index; set on arp-snapshot
}

// DNSCacheEntry carries a single Windows DNS resolver cache entry.
type DNSCacheEntry struct {
	Name string `json:"name"`
	Type string `json:"type"` // "A", "AAAA", "CNAME", "PTR", "MX", etc.
}

// CacheOpResult carries the result of a cache-manipulation command:
// "arp-delete", "arp-clear", "dns-delete", "dns-clear", or "route-delete".
type CacheOpResult struct {
	Op  string `json:"op"`
	OK  bool   `json:"ok"`
	Err string `json:"err,omitempty"`
}

// RouteEntry carries a single IPv4 routing-table entry streamed from service to GUI.
type RouteEntry struct {
	Dest     string `json:"dest"`
	Mask     string `json:"mask"`
	Gateway  string `json:"gateway"`
	IfIndex  uint32 `json:"if_index,omitempty"`
	Metric   uint32 `json:"metric,omitempty"`
	Protocol string `json:"protocol,omitempty"`
	Type     string `json:"type,omitempty"`
	Policy   uint32 `json:"policy,omitempty"`
}

// NetBIOSMsg carries the result of a NetBIOS name query.
type NetBIOSMsg struct {
	IP   string `json:"ip"`
	Name string `json:"name"`
}

// PTRResult carries a background reverse-DNS enrichment result.
type PTRResult struct {
	IP       string `json:"ip"`
	Hostname string `json:"hostname"`
}

// ResolveResult carries the result of a forward DNS lookup ("resolve" command).
type ResolveResult struct {
	Hostname string            `json:"hostname"`
	IPs      []string          `json:"ips,omitempty"`
	PTRNames map[string]string `json:"ptr_names,omitempty"` // IP → PTR hostname (may be absent for some IPs)
	Err      string            `json:"err,omitempty"`
}

// ---------------------------------------------------------------------------
// Service IPC transport helpers
// ---------------------------------------------------------------------------

// NewServiceTLS generates an ephemeral ECDSA P-256 self-signed TLS certificate
// for use as the service listener. It returns:
//   - tcpLn: the underlying TCP listener (caller may call SetDeadline on it)
//   - tlsCfg: a *tls.Config with the cert set (wrap tcpLn with tls.NewListener)
//   - fingerprint: the hex-encoded SHA-256 hash of the cert's raw DER bytes
//
// Security model: The private key never leaves the parent process. The
// fingerprint is passed to the subprocess via argv; even if a local process
// reads /proc/<pid>/cmdline (Linux) or the process command line (Windows),
// knowing only the fingerprint cannot impersonate the TLS server — that
// requires the private key. All session traffic is encrypted (TLS 1.3).
func NewServiceTLS() (tcpLn *net.TCPListener, tlsCfg *tls.Config, fingerprint string, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, "", fmt.Errorf("service TLS key: %w", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "net-scope-service"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, "", fmt.Errorf("service TLS cert: %w", err)
	}
	sum := sha256.Sum256(certDER)
	fingerprint = hex.EncodeToString(sum[:])

	tlsCfg = &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{certDER},
			PrivateKey:  key,
		}},
		MinVersion: tls.VersionTLS13,
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, nil, "", fmt.Errorf("service listener: %w", err)
	}
	tcpLn = ln.(*net.TCPListener)
	return tcpLn, tlsCfg, fingerprint, nil
}

// DialService connects to a service subprocess at addr over TLS, verifying the
// server certificate against the expected hex-encoded SHA-256 fingerprint.
// Returns a net.Conn ready for use with RunServiceConn.
func DialService(addr, fingerprint string) (net.Conn, error) {
	conn, err := tls.Dial("tcp", addr, &tls.Config{
		// InsecureSkipVerify bypasses the system CA chain because the cert is
		// self-signed. Authenticity is established by VerifyConnection below,
		// which pins the exact cert fingerprint received from the parent process.
		InsecureSkipVerify: true, //nolint:gosec
		MinVersion:         tls.VersionTLS13,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("service: no server certificate presented")
			}
			actual := sha256.Sum256(cs.PeerCertificates[0].Raw)
			if hex.EncodeToString(actual[:]) != fingerprint {
				return errors.New("service: TLS certificate fingerprint mismatch — possible connection hijack")
			}
			return nil
		},
	})
	if err != nil {
		return nil, fmt.Errorf("service dial: %w", err)
	}
	return conn, nil
}

// ---------------------------------------------------------------------------
// Service — runs inside the elevated (or user-level) subprocess
// ---------------------------------------------------------------------------

// RunServiceConn is the main loop run by the service subprocess.
// It handles commands over a single connection, staying alive until the GUI
// sends "shutdown" or closes the connection.
//
// Scans and probes run in separate goroutines so the command loop remains
// responsive (e.g. a "stop" command cancels an in-progress scan immediately).
// All concurrent writes to enc are serialised by encMu.
//
// The connection must already be authenticated (TLS handshake completed by
// DialService on the subprocess side and tls.NewListener on the parent side).
func RunServiceConn(conn net.Conn) error {
	defer conn.Close()

	// connCtx is cancelled when the connection ends, stopping background goroutines.
	connCtx, connCancel := context.WithCancel(context.Background())
	defer connCancel()

	dec := json.NewDecoder(conn)
	enc := json.NewEncoder(conn)
	var encMu sync.Mutex

	// safeSend serialises concurrent writes to the JSON encoder.
	safeSend := func(msg ServiceMsg) error {
		encMu.Lock()
		defer encMu.Unlock()
		return enc.Encode(msg)
	}

	// Announce readiness and elevation state. Authentication has already been
	// established by the TLS handshake; no additional token exchange needed.
	if err := safeSend(ServiceMsg{Ready: true, Elevated: IsElevated()}); err != nil {
		return fmt.Errorf("service ready: %w", err)
	}
	// PTR resolver goroutine starts immediately and lives for the connection.
	_ = safeSend(ServiceMsg{WorkerStatus: &WorkerStatus{Name: "PTR Resolver", Running: true}})

	// ptrQueue receives IPs that need background PTR (reverse-DNS) resolution.
	// Buffered to absorb a full /24 without blocking the scan streamer.
	ptrQueue := make(chan string, 256)
	ptrSeen := make(map[string]bool)
	var ptrMu sync.Mutex

	go func() {
		for {
			select {
			case <-connCtx.Done():
				return
			case ip, ok := <-ptrQueue:
				if !ok {
					return
				}
				ptrMu.Lock()
				already := ptrSeen[ip]
				if !already {
					ptrSeen[ip] = true
				}
				ptrMu.Unlock()
				if already {
					continue
				}
				name := reverseDNS(connCtx, net.ParseIP(ip), time.Second)
				if name != "" {
					_ = safeSend(ServiceMsg{PTRUpdate: &PTRResult{IP: ip, Hostname: name}})
				}
				// Throttle to avoid bursting the local resolver.
				select {
				case <-connCtx.Done():
					return
				case <-time.After(100 * time.Millisecond):
				}
			}
		}
	}()

	var scanCancel context.CancelFunc
	var dhcpCancel context.CancelFunc
	var bcastCancel context.CancelFunc
	var arpCancel context.CancelFunc

	// ---------------------------------------------------------------------------
	// Per-connection service registry — unified Service objects that accumulate
	// evidence from all port scans and broadcast discoveries within this session.
	// The registry persists across scans; it is NOT reset on "scan" commands.
	// ---------------------------------------------------------------------------

	type svcRegKey struct {
		ip   string
		port int    // 0 for discovery-only services
		sub  string // service-type key for port-0 discovery services; source-agnostic
	}
	svcReg := map[svcRegKey]*Service{}
	var svcRegMu sync.Mutex

	// normalizeIP canonicalises the IP string so that IPv4 addresses compare
	// equal regardless of whether they arrived from a 4-byte or 16-byte net.IP.
	normalizeIP := func(ip string) string {
		if p := net.ParseIP(ip); p != nil {
			if p4 := p.To4(); p4 != nil {
				return p4.String()
			}
			return p.String()
		}
		return ip
	}

	// mergeConf accumulates confidence from a new evidence source. The higher
	// value is used as the base; the lower contributes a quarter of its value
	// as a corroboration bonus. Result is capped at 100.
	mergeConf := func(current, add uint8) uint8 {
		if add > current {
			current, add = add, current
		}
		sum := uint16(current) + uint16(add)/4
		if sum > 100 {
			return 100
		}
		return uint8(sum)
	}

	// upsertObs inserts or replaces a single observation by source+key.
	upsertObs := func(obs []Observation, src, key, val string) []Observation {
		if val == "" {
			return obs
		}
		for i := range obs {
			if obs[i].Source == src && obs[i].Key == key {
				obs[i].Value = val
				return obs
			}
		}
		return append(obs, Observation{Source: src, Key: key, Value: val})
	}

	// upsertPortSvc merges a PortService into the registry and emits SvcUpdate.
	upsertPortSvc := func(ip string, ps PortService) {
		ip = normalizeIP(ip)
		key := svcRegKey{ip: ip, port: ps.Port}
		now := time.Now()
		svcRegMu.Lock()
		s, exists := svcReg[key]
		if !exists {
			s = &Service{ID: ps.ID, IP: ip, Port: ps.Port, FirstSeen: now}
			svcReg[key] = s
		}
		s.LastSeen = now
		if ps.Name != "" {
			s.Name = ps.Name
		} else if s.Name == "" {
			s.Name = "port/" + strconv.Itoa(ps.Port)
		}
		if ps.Version != "" {
			s.Version = ps.Version
		}
		s.Confidence = mergeConf(s.Confidence, ps.Confidence)
		s.Obs = upsertObs(s.Obs, "banner", "name", ps.Name)
		s.Obs = upsertObs(s.Obs, "banner", "version", ps.Version)
		s.Obs = upsertObs(s.Obs, "banner", "banner", ps.Banner)
		s.Obs = upsertObs(s.Obs, "banner", "tls_cert", ps.TLSCert)
		s.Obs = upsertObs(s.Obs, "banner", "alpn", ps.ALPN)
		if ps.Confidence > 0 {
			s.Obs = upsertObs(s.Obs, "banner", "confidence", strconv.Itoa(int(ps.Confidence))+"%")
		}
		for k, v := range ps.Details {
			s.Obs = upsertObs(s.Obs, "banner", k, v)
		}
		ApplySignatures(s)
		clone := *s
		clone.Obs = make([]Observation, len(s.Obs))
		copy(clone.Obs, s.Obs)
		clone.Capabilities = copyClaimMap(s.Capabilities)
		clone.Fingerprints = copyClaimMap(s.Fingerprints)
		svcRegMu.Unlock()
		_ = safeSend(ServiceMsg{SvcUpdate: &clone})
	}

	// upsertDiscoverySvc merges a ServiceInfo into the registry and emits SvcUpdate.
	upsertDiscoverySvc := func(ip string, svc ServiceInfo) {
		ip = normalizeIP(ip)
		key := svcRegKey{ip: ip}
		if svc.Port > 0 {
			key.port = svc.Port
		} else {
			// Port-0 discovery: the SRV record was not yet resolved (mDNS race)
			// or the announcement genuinely has no listening port (e.g. Apple's
			// _device-info._tcp). For service types that have a single well-known
			// port, use that port as the key so the entry merges with any existing
			// banner-scanned entry on the same host rather than creating a duplicate.
			if wkp := SvcTypeWellKnownPort(svc.Type); wkp > 0 {
				key.port = wkp
			} else {
				// Unknown type or metadata-only advertisement (no real listener,
				// no reliable port). Key by type so all sources that emit the same
				// type for the same IP agree on a single entry.
				key.sub = svc.Type
			}
		}
		now := time.Now()
		friendlyName := ServiceFriendlyName(svc.Type)
		// Confidence: 80 when we know the protocol (it's in our friendly-name
		// table), 50 when we could only guess from the raw type string. A 50
		// is below the default display threshold so unknown UPnP service types
		// are suppressed in the main Services tab but visible in View All.
		conf := uint8(80)
		if friendlyName == svc.Type {
			conf = 50
		}
		svcRegMu.Lock()
		s, exists := svcReg[key]
		if !exists {
			s = &Service{
				ID:         newPortServiceID(),
				IP:         ip,
				Port:       key.port, // use resolved key port (may differ from svc.Port when port=0 + well-known fallback)
				Confidence: conf,
				FirstSeen:  now,
			}
			svcReg[key] = s
		} else {
			s.Confidence = mergeConf(s.Confidence, conf)
		}
		s.LastSeen = now
		// Prefer the friendly protocol/type name; never overwrite a name
		// that was derived from a banner probe.
		hasBannerName := false
		for _, o := range s.Obs {
			if o.Source == "banner" && o.Key == "name" && o.Value != "" {
				hasBannerName = true
				break
			}
		}
		if !hasBannerName {
			if friendlyName != "" && friendlyName != svc.Type {
				s.Name = friendlyName
			} else if s.Name == "" && svc.Name != "" {
				s.Name = cleanDNSLabel(svc.Name)
			}
		}
		src := strings.ToLower(svc.Source)
		if svc.Name != "" {
			// Strip DNS label backslash escapes before storing the instance name
			// so the raw value is already clean for display.
			s.Obs = upsertObs(s.Obs, src, "instance", cleanDNSLabel(svc.Name))
		}
		if svc.Type != "" {
			s.Obs = upsertObs(s.Obs, src, "type", svc.Type)
		}
		for _, d := range svc.Details {
			if colon := strings.Index(d, ":"); colon > 0 {
				s.Obs = upsertObs(s.Obs, src, d[:colon], d[colon+1:])
			} else if d != "" {
				s.Obs = upsertObs(s.Obs, src, "detail", d)
			}
		}
		ApplySignatures(s)
		clone := *s
		clone.Obs = make([]Observation, len(s.Obs))
		copy(clone.Obs, s.Obs)
		clone.Capabilities = copyClaimMap(s.Capabilities)
		clone.Fingerprints = copyClaimMap(s.Fingerprints)
		svcRegMu.Unlock()
		_ = safeSend(ServiceMsg{SvcUpdate: &clone})
	}

	for {
		var cmd ServiceCmd
		if err := dec.Decode(&cmd); err != nil {
			return nil // connection closed — normal shutdown
		}

		switch cmd.Cmd {
		case "scan":
			// Cancel any in-progress scan before starting a new one.
			if scanCancel != nil {
				scanCancel()
			}
			if cmd.Config == nil || cmd.Target == "" {
				_ = safeSend(ServiceMsg{Err: "scan: missing target or config"})
				continue
			}
			ctx, cancel := context.WithCancel(context.Background())
			scanCancel = cancel
			scanID := cmd.ScanID

			// Expand the target now so we can pre-emit "queued" states for
			// every host before the scanner starts. ExpandTarget is
			// inexpensive (no I/O) and the worst-case /16 is 65535 items.
			// Failure here falls through gracefully — sc.Scan will also fail
			// and send the proper error message.
			if hosts, expandErr := ExpandTarget(cmd.Target); expandErr == nil {
				for _, ip := range hosts {
					ipStr := ip.String()
					wi := WorkItem{IP: ipStr, State: WorkQueued}
					_ = safeSend(ServiceMsg{WorkUpdate: &wi, ScanID: scanID})
				}
			}

			sc := NewScanner(*cmd.Config)
			ch, err := sc.Scan(ctx, cmd.Target)
			if err != nil {
				scanCancel()
				scanCancel = nil
				_ = safeSend(ServiceMsg{Err: "scan: " + err.Error(), ScanID: scanID})
				continue
			}
			_ = safeSend(ServiceMsg{WorkerStatus: &WorkerStatus{Name: "Port Scanner", Running: true}})
			// Stream results in a goroutine so the command loop stays responsive.
			go func() {
				for r := range ch {
					rCopy := r
					ipStr := rCopy.IP.String()
					// Derive work-item state from result shape:
					//   Partial:true  → host is alive; deep probe still in progress
					//   Partial:false, Alive:true  → probe complete
					//   Partial:false, Alive:false → host did not respond
					var wiState WorkItemState
					switch {
					case rCopy.Partial && rCopy.Alive:
						wiState = WorkRunning
					case !rCopy.Partial && rCopy.Alive:
						wiState = WorkDone
					default:
						wiState = WorkDead
					}
					wi := WorkItem{IP: ipStr, State: wiState}
					if werr := safeSend(ServiceMsg{Result: &rCopy, WorkUpdate: &wi, ScanID: scanID}); werr != nil {
						return
					}
					// Upsert each discovered PortService into the session registry.
					for _, ps := range rCopy.PortServices {
						upsertPortSvc(ipStr, ps)
					}
					// Queue hosts without hostnames for background PTR resolution.
					if rCopy.Hostname == "" && rCopy.IP != nil {
						select {
						case ptrQueue <- ipStr:
						default: // queue full; skip rather than block
						}
					}
				}
				_ = safeSend(ServiceMsg{Done: true, Stats: &sc.Stats, ScanID: scanID})
				_ = safeSend(ServiceMsg{WorkerStatus: &WorkerStatus{Name: "Port Scanner", Running: false}})
			}()

		case "stop":
			if scanCancel != nil {
				scanCancel()
				scanCancel = nil
			}

		case "probe":
			if cmd.Probe == nil || cmd.Target == "" {
				_ = safeSend(ServiceMsg{Err: "probe: missing target or spec"})
				continue
			}
			spec := *cmd.Probe
			target := cmd.Target
			proxy := cmd.SOCKSProxy
			go func() {
				dial, _ := MakeDialFunc(proxy)
				result := RunProbe(context.Background(), target, spec, 3*time.Second, dial)
				_ = safeSend(ServiceMsg{ProbeResult: &result})
			}()

		case "dhcp-start":
			if dhcpCancel != nil {
				break // already running
			}
			if !IsElevated() {
				_ = safeSend(ServiceMsg{Err: "dhcp-start: requires elevation"})
				continue
			}
			ctx, cancel := context.WithCancel(context.Background())
			dhcpCancel = cancel
			ch := make(chan DHCPEvent, 64)
			if err := ListenDHCP(ctx, ch); err != nil {
				dhcpCancel()
				dhcpCancel = nil
				_ = safeSend(ServiceMsg{Err: "dhcp-start: " + err.Error()})
				continue
			}
			_ = safeSend(ServiceMsg{WorkerStatus: &WorkerStatus{Name: "DHCP Capture", Running: true}})
			go func() {
				for evt := range ch {
					e := evt
					if werr := safeSend(ServiceMsg{DHCP: &e}); werr != nil {
						return
					}
				}
			}()

		case "dhcp-stop":
			if dhcpCancel != nil {
				dhcpCancel()
				dhcpCancel = nil
				_ = safeSend(ServiceMsg{WorkerStatus: &WorkerStatus{Name: "DHCP Capture", Running: false}})
			}

		case "bcast-start":
			if bcastCancel != nil {
				break // already running
			}
			bl := 3 * time.Second
			if cmd.BcastListen != "" {
				if d, err := time.ParseDuration(cmd.BcastListen); err == nil && d > 0 {
					bl = d
				}
			}
			ctx, cancel := context.WithCancel(context.Background())
			bcastCancel = cancel
			go func() {
				probeErr := ProbeListenerSupport()
				errStr := ""
				if probeErr != nil {
					errStr = probeErr.Error()
				}
				_ = safeSend(ServiceMsg{BcastReady: true, BcastErr: errStr})
				if probeErr != nil {
					return
				}
				_ = safeSend(ServiceMsg{WorkerStatus: &WorkerStatus{Name: "Broadcast Listener", Running: true}})
				ListenBroadcast(ctx, bl, func(ip string, svc ServiceInfo) {
					svcCopy := svc
					_ = safeSend(ServiceMsg{BcastSvc: &svcCopy, BcastIP: ip})
					// Merge into the session service registry.
					upsertDiscoverySvc(ip, svcCopy)
					// Queue IP for background PTR lookup so discovery-only hosts
					// get a DNS hostname without requiring a full scan.
					select {
					case ptrQueue <- ip:
					default:
					}
				})
				_ = safeSend(ServiceMsg{WorkerStatus: &WorkerStatus{Name: "Broadcast Listener", Running: false}})
			}()

		case "bcast-stop":
			if bcastCancel != nil {
				bcastCancel()
				bcastCancel = nil
			}

		case "arp-start":
			if arpCancel != nil {
				break // already running
			}
			ctx, cancel := context.WithCancel(context.Background())
			arpCancel = cancel
			_ = safeSend(ServiceMsg{WorkerStatus: &WorkerStatus{Name: "ARP Poll", Running: true}})
			go func() {
				t := time.NewTicker(5 * time.Second)
				defer t.Stop()
				for {
					select {
					case <-ctx.Done():
						return
					case <-t.C:
						for ip, mac := range ReadARPTable() {
							entry := &ARPResult{IP: ip, MAC: mac.String()}
							if werr := safeSend(ServiceMsg{ARPEntry: entry}); werr != nil {
								return
							}
						}
					}
				}
			}()

		case "arp-stop":
			if arpCancel != nil {
				arpCancel()
				arpCancel = nil
				_ = safeSend(ServiceMsg{WorkerStatus: &WorkerStatus{Name: "ARP Poll", Running: false}})
			}

		case "arp-snapshot":
			// One-shot: stream the full ARP table and signal completion.
			for _, e := range ReadARPTableFull() {
				entry := e
				if werr := safeSend(ServiceMsg{ARPEntry: &entry, ARPSnapshot: true}); werr != nil {
					return werr
				}
			}
			_ = safeSend(ServiceMsg{ARPSnapDone: true})

		case "arp-delete":
			if cmd.Target == "" {
				continue
			}
			target := cmd.Target
			go func() {
				err := DeleteARPEntry(target)
				op := &CacheOpResult{Op: "arp-delete", OK: err == nil}
				if err != nil {
					op.Err = err.Error()
				}
				_ = safeSend(ServiceMsg{CacheOp: op})
			}()

		case "arp-clear":
			go func() {
				err := FlushARPCache(0)
				op := &CacheOpResult{Op: "arp-clear", OK: err == nil}
				if err != nil {
					op.Err = err.Error()
				}
				_ = safeSend(ServiceMsg{CacheOp: op})
			}()

		case "dns-snapshot":
			// One-shot: stream the full DNS resolver cache and signal completion.
			for _, e := range ReadDNSCache() {
				entry := e
				if werr := safeSend(ServiceMsg{DNSEntry: &entry}); werr != nil {
					return werr
				}
			}
			_ = safeSend(ServiceMsg{DNSSnapDone: true})

		case "dns-delete":
			if cmd.Target == "" {
				continue
			}
			target := cmd.Target
			go func() {
				err := DeleteDNSCacheEntry(target)
				op := &CacheOpResult{Op: "dns-delete", OK: err == nil}
				if err != nil {
					op.Err = err.Error()
				}
				_ = safeSend(ServiceMsg{CacheOp: op})
			}()

		case "dns-clear":
			go func() {
				err := FlushDNSCache()
				op := &CacheOpResult{Op: "dns-clear", OK: err == nil}
				if err != nil {
					op.Err = err.Error()
				}
				_ = safeSend(ServiceMsg{CacheOp: op})
			}()

		case "route-snapshot":
			// One-shot: stream the full routing table and signal completion.
			for _, e := range ReadRouteTable() {
				entry := e
				if werr := safeSend(ServiceMsg{RouteEntry: &entry}); werr != nil {
					return werr
				}
			}
			_ = safeSend(ServiceMsg{RouteSnapDone: true})

		case "route-delete":
			if cmd.Target == "" {
				continue
			}
			target := cmd.Target
			go func() {
				err := DeleteRouteEntry(target)
				op := &CacheOpResult{Op: "route-delete", OK: err == nil}
				if err != nil {
					op.Err = err.Error()
				}
				_ = safeSend(ServiceMsg{CacheOp: op})
			}()

		case "netbios":
			if cmd.Target == "" {
				continue
			}
			target := cmd.Target
			go func() {
				parsed := net.ParseIP(target)
				if parsed == nil {
					return
				}
				name := ProbeNetBIOS(parsed, 2*time.Second)
				if name == "" {
					return
				}
				_ = safeSend(ServiceMsg{Netbios: &NetBIOSMsg{IP: target, Name: name}})
			}()

		case "proxy-test":
			if cmd.SOCKSProxy == "" {
				continue
			}
			proxy := cmd.SOCKSProxy
			go func() {
				conn, err := net.DialTimeout("tcp", proxy, 5*time.Second)
				if err != nil {
					_ = safeSend(ServiceMsg{ProxyErr: err.Error()})
					return
				}
				conn.Close()
				_ = safeSend(ServiceMsg{ProxyOK: true})
			}()

		case "oui-update":
			dir := cmd.DataDir
			go func() {
				_, err := DownloadOUIDB(dir)
				if err != nil {
					_ = safeSend(ServiceMsg{OUIErr: err.Error()})
					return
				}
				_ = safeSend(ServiceMsg{OUIComplete: true})
			}()

		case "resolve":
			if cmd.Target == "" {
				continue
			}
			target := cmd.Target
			go func() {
				addrs, err := net.DefaultResolver.LookupHost(context.Background(), target)
				if err != nil {
					_ = safeSend(ServiceMsg{ResolveResult: &ResolveResult{Hostname: target, Err: err.Error()}})
					return
				}
				// For each resolved IP, perform a PTR lookup. The A record
				// hostname and the PTR records are independent: a round-robin A
				// record can map to many IPs, each with a completely different
				// PTR. We must not assume they are the same.
				ptrNames := make(map[string]string, len(addrs))
				var mu sync.Mutex
				var wg sync.WaitGroup
				for _, addr := range addrs {
					wg.Add(1)
					go func(ip string) {
						defer wg.Done()
						ptrs, ptrErr := net.DefaultResolver.LookupAddr(context.Background(), ip)
						if ptrErr == nil && len(ptrs) > 0 {
							name := ptrs[0]
							// PTR records include a trailing dot; strip it.
							if len(name) > 0 && name[len(name)-1] == '.' {
								name = name[:len(name)-1]
							}
							mu.Lock()
							ptrNames[ip] = name
							mu.Unlock()
						}
					}(addr)
				}
				wg.Wait()
				_ = safeSend(ServiceMsg{ResolveResult: &ResolveResult{Hostname: target, IPs: addrs, PTRNames: ptrNames}})
			}()

		case "shutdown":
			if scanCancel != nil {
				scanCancel()
			}
			if dhcpCancel != nil {
				dhcpCancel()
			}
			if bcastCancel != nil {
				bcastCancel()
			}
			if arpCancel != nil {
				arpCancel()
			}
			return nil

		default:
			_ = safeSend(ServiceMsg{Err: "unknown command: " + cmd.Cmd})
		}
	}
}
