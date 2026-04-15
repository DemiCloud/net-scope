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
	"io"
	"math/big"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/demicloud/net-scope/internal/netinfo"
)

// ---------------------------------------------------------------------------
// Wire types — GUI ↔ service (newline-delimited JSON over TLS localhost)
// ---------------------------------------------------------------------------

// PortScanSpec describes a targeted single-host port scan issued via "port-scan".
type PortScanSpec struct {
	// Mode is one of "default" (DefaultConfig().Ports), "specific" (the Ports
	// list below), or "all" (all TCP ports 1–65535).
	Mode  string `json:"mode"`
	// Ports is the explicit port list for "specific" mode.
	Ports []int  `json:"ports,omitempty"`
	// RunID is a client-assigned token echoed in every PortScanEntry so the
	// dialog can discard stale results from a superseded run.
	RunID string `json:"run_id"`
}

// PortScanEntry carries the result of a single open port from a "port-scan"
// stream. The final message has Total set and no Port value.
type PortScanEntry struct {
	RunID string `json:"run_id"`
	Port  int    `json:"port,omitempty"`
	Open  bool   `json:"open,omitempty"`
	// Total is the total number of ports that were checked; set only on the
	// final (done) message bundled with PortScanDone=true.
	Total int    `json:"total,omitempty"`
}

// ServiceCmd is sent by the GUI to the service.
type ServiceCmd struct {
	// Cmd is one of: "scan", "stop", "probe", "port-scan", "port-scan-stop",
	// "dhcp-start", "dhcp-stop",
	// "bcast-start", "bcast-stop", "arp-start", "arp-stop",
	// "arp-snapshot", "arp-delete", "arp-clear",
	// "dns-snapshot", "dns-delete", "dns-clear",
	// "route-snapshot", "route-delete",
	// "socket-snapshot",
	// "hosts-snapshot", "hosts-add", "hosts-delete",
	// "if-snapshot",
	// "eventlog-snapshot",
	// "wake",
	// "netbios", "proxy-test", "oui-update", "shutdown"
	Cmd        string     `json:"cmd"`
	Target     string     `json:"target,omitempty"`
	Config     *Config    `json:"config,omitempty"`
	// ScanID is echoed back in every Result and Done message for this scan.
	// The GUI uses it to discard results from superseded scans.
	ScanID     uint64     `json:"scan_id,omitempty"`
	// Probe is set for the "probe" command.
	Probe      *ProbeSpec `json:"probe,omitempty"`
	// PortScan is set for the "port-scan" command.
	PortScan   *PortScanSpec `json:"port_scan,omitempty"`
	// SOCKSProxy is the SOCKS5 address to use for the probe (empty = direct).
	// Also used for "proxy-test".
	SOCKSProxy string     `json:"socks_proxy,omitempty"`
	// BcastListen is the Go duration string for the broadcast window ("bcast-start").
	BcastListen string    `json:"bcast_listen,omitempty"`
	// DataDir is the filesystem path for outputs that need it ("oui-update").
	DataDir     string    `json:"data_dir,omitempty"`
	// HostsAdd carries parameters for the "hosts-add" command.
	HostsAdd    *HostsAddParams `json:"hosts_add,omitempty"`
	// WolMAC is the target MAC for the "wake" command (e.g. "aa:bb:cc:dd:ee:ff").
	WolMAC       string `json:"wol_mac,omitempty"`
	// WolBroadcast is the UDP broadcast address for the "wake" command.
	// Defaults to "255.255.255.255" when empty.
	WolBroadcast string `json:"wol_broadcast,omitempty"`
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
	DHCP     *netinfo.DHCPEvent   `json:"dhcp,omitempty"`
	// ProbeResult carries the result of a single on-demand host probe (simple path).
	ProbeResult *ProbeResult `json:"probe_result,omitempty"`
	// ProbeEvent carries one streaming line from a deep probe run (ExtProbeID path).
	// The dialog receives N ProbeEvent messages, the last of which has Done=true.
	ProbeEvent *ProbeEvent `json:"probe_event,omitempty"`
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
	ARPEntry    *netinfo.ARPResult `json:"arp_entry,omitempty"`
	ARPSnapshot bool               `json:"arp_snapshot,omitempty"`
	// ARPSnapDone signals the end of an "arp-snapshot" stream.
	ARPSnapDone bool               `json:"arp_snap_done,omitempty"`
	// DNSEntry carries a single DNS resolver cache entry ("dns-snapshot" stream).
	DNSEntry    *netinfo.DNSCacheEntry `json:"dns_entry,omitempty"`
	// DNSSnapDone signals the end of a "dns-snapshot" stream.
	DNSSnapDone bool                   `json:"dns_snap_done,omitempty"`
	// CacheOp carries the result of an "arp-delete", "arp-clear", "dns-delete",
	// "dns-clear", or "route-delete" command.
	CacheOp    *CacheOpResult `json:"cache_op,omitempty"`
	// RouteEntry carries a single routing-table entry ("route-snapshot" stream).
	RouteEntry    *netinfo.RouteEntry `json:"route_entry,omitempty"`
	// RouteSnapDone signals the end of a "route-snapshot" stream.
	RouteSnapDone bool                `json:"route_snap_done,omitempty"`
	// SocketEntry carries a single socket from a "socket-snapshot" stream.
	SocketEntry    *netinfo.SocketEntry `json:"socket_entry,omitempty"`
	// SocketSnapDone signals the end of a "socket-snapshot" stream.
	SocketSnapDone bool                 `json:"socket_snap_done,omitempty"`
	// HostsEntry carries a single hosts-file entry from a "hosts-snapshot" stream.
	HostsEntry    *netinfo.HostsEntry `json:"hosts_entry,omitempty"`
	// HostsSnapDone signals the end of a "hosts-snapshot" stream.
	HostsSnapDone bool                `json:"hosts_snap_done,omitempty"`
	// IfEntry carries a single local network interface from an "if-snapshot" stream.
	IfEntry    *netinfo.InterfaceEntry `json:"if_entry,omitempty"`
	// IfSnapDone signals the end of an "if-snapshot" stream.
	IfSnapDone bool                    `json:"if_snap_done,omitempty"`
	// EventLogEntry carries a single Windows Event Log entry from an "eventlog-snapshot" stream.
	EventLogEntry    *netinfo.EventLogEntry `json:"eventlog_entry,omitempty"`
	// EventLogSnapDone signals the end of an "eventlog-snapshot" stream.
	EventLogSnapDone bool                   `json:"eventlog_snap_done,omitempty"`
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
	// ProbeHost announces that a manual deep probe succeeded; the GUI should
	// ensure this IP appears in the Hosts tab. PTR enrichment arrives separately.
	ProbeHost *ProbeHostResult `json:"probe_host,omitempty"`
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
	// WolResult carries the outcome of a "wake" command.
	WolResult *WolResult `json:"wol_result,omitempty"`
	// PortScanEntry carries one open-port result from a "port-scan" stream.
	// The final message has PortScanDone=true and Total populated.
	PortScanEntry *PortScanEntry `json:"port_scan_entry,omitempty"`
	// PortScanDone signals the end of a "port-scan" stream; always bundled
	// with a PortScanEntry carrying the total port count.
	PortScanDone bool `json:"port_scan_done,omitempty"`
}

// CacheOpResult carries the result of a cache-manipulation command:
// "arp-delete", "arp-clear", "dns-delete", "dns-clear", or "route-delete".
type CacheOpResult struct {
	Op  string `json:"op"`
	OK  bool   `json:"ok"`
	Err string `json:"err,omitempty"`
}

// HostsAddParams carries the parameters for a "hosts-add" command.
type HostsAddParams struct {
	IP        string   `json:"ip"`
	Hostnames []string `json:"hostnames"`
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

// ProbeHostResult announces that a successful manual deep probe reached an IP.
// The GUI adds this IP to the Hosts tab; PTR enrichment arrives via PTRUpdate.
type ProbeHostResult struct {
	IP       string `json:"ip"`
	Port     int    `json:"port,omitempty"`
	Protocol string `json:"protocol,omitempty"` // human-readable probe name, e.g. "SMTP"
}

// WolResult carries the outcome of a "wake" (Wake-on-LAN) command.
type WolResult struct {
	MAC string `json:"mac"`
	Err string `json:"err,omitempty"` // empty on success
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
// cloneService returns a deep copy of s with independent Obs, Capabilities,
// and Fingerprints slices so it is safe to send over the wire without holding
// the registry lock.
func cloneService(s *Service) Service {
	clone := *s
	clone.Obs = make([]Observation, len(s.Obs))
	copy(clone.Obs, s.Obs)
	clone.Capabilities = copyClaimMap(s.Capabilities)
	clone.Fingerprints = copyClaimMap(s.Fingerprints)
	return clone
}

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
	if err := safeSend(ServiceMsg{Ready: true, Elevated: netinfo.IsElevated()}); err != nil {
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
	var portScanCancel context.CancelFunc

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

	// asyncCacheOp runs fn in a goroutine and sends a CacheOpResult with opName.
	asyncCacheOp := func(opName string, fn func() error) {
		go func() {
			err := fn()
			op := &CacheOpResult{Op: opName, OK: err == nil}
			if err != nil {
				op.Err = err.Error()
			}
			_ = safeSend(ServiceMsg{CacheOp: op})
		}()
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
		clone := cloneService(s)
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
		clone := cloneService(s)
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

		case "port-scan":
			if cmd.PortScan == nil || cmd.Target == "" {
				_ = safeSend(ServiceMsg{Err: "port-scan: missing target or spec"})
				continue
			}
			// Cancel any in-progress port scan first.
			if portScanCancel != nil {
				portScanCancel()
				portScanCancel = nil
			}
			ip := net.ParseIP(normalizeIP(cmd.Target))
			if ip == nil {
				_ = safeSend(ServiceMsg{Err: "port-scan: invalid IP: " + cmd.Target})
				continue
			}
			spec := *cmd.PortScan
			var ports []int
			switch spec.Mode {
			case "specific":
				ports = spec.Ports
			case "all":
				ports = allPortsRange()
			default: // "default"
				ports = DefaultConfig().Ports
			}
			if len(ports) == 0 {
				_ = safeSend(ServiceMsg{Err: "port-scan: no ports to scan"})
				continue
			}
			ctx, cancel := context.WithCancel(connCtx)
			portScanCancel = cancel
			runID := spec.RunID
			total := len(ports)
			go func() {
				defer cancel()
				ScanPortsStreaming(ctx, ip, ports, DefaultConfig().Timeout, nil, 500, func(port int, open bool) {
					if !open {
						return // only stream open ports
					}
					_ = safeSend(ServiceMsg{PortScanEntry: &PortScanEntry{
						RunID: runID,
						Port:  port,
						Open:  true,
					}})
				})
				_ = safeSend(ServiceMsg{
					PortScanDone:  true,
					PortScanEntry: &PortScanEntry{RunID: runID, Total: total},
				})
			}()

		case "port-scan-stop":
			if portScanCancel != nil {
				portScanCancel()
				portScanCancel = nil
			}

		case "probe":
			if cmd.Probe == nil || cmd.Target == "" {
				_ = safeSend(ServiceMsg{Err: "probe: missing target or spec"})
				continue
			}
			spec := *cmd.Probe
			target := cmd.Target
			proxy := cmd.SOCKSProxy

			if spec.ExtProbeID != "" {
				// Deep probe: streaming ProbeEvent path.
				runID := spec.RunID
				port := spec.Port
				go func() {
					dp, ok := DeepProbeByID(spec.ExtProbeID)
					if !ok {
						_ = safeSend(ServiceMsg{ProbeEvent: &ProbeEvent{
							RunID: runID,
							Err:   "unknown probe: " + spec.ExtProbeID,
							Done:  true,
						}})
						return
					}
					if port == 0 {
						port = dp.DefaultPort
					}

					// Resolve target to a concrete IP address. If the caller supplied
					// a hostname (e.g. "smtp.gmail.com"), resolve it to the first
					// address before probing so the service registry key is always an
					// IP and PTR/host enrichment works correctly.
					probeIP := normalizeIP(target)
					if net.ParseIP(target) == nil {
						// target is a hostname — resolve to first address.
						addrs, rErr := net.DefaultResolver.LookupHost(context.Background(), target)
						if rErr != nil || len(addrs) == 0 {
							_ = safeSend(ServiceMsg{ProbeEvent: &ProbeEvent{
								RunID: runID,
								Err:   "cannot resolve " + target + ": " + func() string { if rErr != nil { return rErr.Error() }; return "no addresses" }(),
								Done:  true,
							}})
							return
						}
						probeIP = normalizeIP(addrs[0])
						_ = safeSend(ServiceMsg{ProbeEvent: &ProbeEvent{
							RunID: runID,
							Text:  "Resolved " + target + " → " + probeIP,
						}})
					}

					dial, _ := MakeDialFunc(proxy)
					emit := func(line string) {
						_ = safeSend(ServiceMsg{ProbeEvent: &ProbeEvent{RunID: runID, Text: line}})
					}
					obs, err := dp.Run(context.Background(), probeIP, port, dial, emit)
					// Merge observations into the session service registry,
					// then notify the GUI to ensure the host appears in the Hosts tab.
					if len(obs) > 0 && port > 0 {
						now := time.Now()
						key := svcRegKey{ip: probeIP, port: port}
						svcRegMu.Lock()
						s, exists := svcReg[key]
						if !exists {
							s = &Service{ID: newPortServiceID(), IP: probeIP, Port: port, FirstSeen: now}
							svcReg[key] = s
						}
						s.LastSeen = now
						// A probe may emit obs("probe", "service_name", ...) to supply a
						// dynamic display name (e.g. Steam reads the game title from the
						// A2S response). These observations are consumed here and not
						// stored in s.Obs — they are a naming side-channel only.
						dynSvcName := ""
						var filteredObs []Observation
						for _, o := range obs {
							if o.Source == "probe" && o.Key == "service_name" {
								dynSvcName = o.Value
							} else {
								filteredObs = append(filteredObs, o)
							}
						}
						// Priority: dynamic (probe-computed) > static (dp.ServiceName) > existing name.
						if dynSvcName != "" {
							s.Name = dynSvcName
						} else if s.Name == "" && dp.ServiceName != "" {
							s.Name = dp.ServiceName
						}
						for _, o := range filteredObs {
							s.Obs = upsertObs(s.Obs, o.Source, o.Key, o.Value)
						}
						ApplySignatures(s)
						clone := cloneService(s)
						svcRegMu.Unlock()
						_ = safeSend(ServiceMsg{SvcUpdate: &clone})

						// Tell the GUI to add this IP to the Hosts tab.
						svcNameForProto := dp.ServiceName
						if svcNameForProto == "" {
							svcNameForProto = dp.Name
						}
						_ = safeSend(ServiceMsg{ProbeHost: &ProbeHostResult{
							IP:       probeIP,
							Port:     port,
							Protocol: svcNameForProto,
						}})
						// Queue for PTR resolution so the host gets a hostname.
						select {
						case ptrQueue <- probeIP:
						default:
						}
					}
					errStr := ""
					if err != nil {
						errStr = err.Error()
					}
					_ = safeSend(ServiceMsg{ProbeEvent: &ProbeEvent{RunID: runID, Done: true, Err: errStr}})
				}()
			} else {
				// Simple probe: single ProbeResult (legacy banner-grab path).
				go func() {
					dial, _ := MakeDialFunc(proxy)
					result := RunProbe(context.Background(), target, spec, 3*time.Second, dial)
					_ = safeSend(ServiceMsg{ProbeResult: &result})
				}()
			}

		case "dhcp-start":
			if dhcpCancel != nil {
				break // already running
			}
			if !netinfo.IsElevated() {
				_ = safeSend(ServiceMsg{Err: "dhcp-start: requires elevation"})
				continue
			}
			ctx, cancel := context.WithCancel(context.Background())
			dhcpCancel = cancel
			ch := make(chan netinfo.DHCPEvent, 64)
			if err := netinfo.ListenDHCP(ctx, ch); err != nil {
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
				for ip, mac := range netinfo.ReadARPTable() {
					entry := &netinfo.ARPResult{IP: ip, MAC: mac.String()}
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
			for _, e := range netinfo.ReadARPTableFull() {
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
			asyncCacheOp("arp-delete", func() error { return netinfo.DeleteARPEntry(target) })

		case "arp-clear":
			asyncCacheOp("arp-clear", func() error { return netinfo.FlushARPCache(0) })

		case "dns-snapshot":
			// One-shot: stream the full DNS resolver cache and signal completion.
			for _, e := range netinfo.ReadDNSCache() {
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
			asyncCacheOp("dns-delete", func() error { return netinfo.DeleteDNSCacheEntry(target) })

		case "dns-clear":
			asyncCacheOp("dns-clear", func() error { return netinfo.FlushDNSCache() })

		case "route-snapshot":
			// One-shot: stream the full routing table and signal completion.
			for _, e := range netinfo.ReadRouteTable() {
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
			asyncCacheOp("route-delete", func() error { return netinfo.DeleteRouteEntry(target) })

		case "socket-snapshot":
			// One-shot: stream all TCP/UDP sockets and signal completion.
			for _, e := range netinfo.ReadSockets() {
				entry := e
				if werr := safeSend(ServiceMsg{SocketEntry: &entry}); werr != nil {
					return werr
				}
			}
			_ = safeSend(ServiceMsg{SocketSnapDone: true})

		case "hosts-snapshot":
			// One-shot: stream all hosts-file entries and signal completion.
			for _, e := range netinfo.ReadHostsFile() {
				entry := e
				if werr := safeSend(ServiceMsg{HostsEntry: &entry}); werr != nil {
					return werr
				}
			}
			_ = safeSend(ServiceMsg{HostsSnapDone: true})

		case "if-snapshot":
			// One-shot: stream all local network interfaces and signal completion.
			for _, e := range netinfo.ReadInterfaces() {
				entry := e
				if werr := safeSend(ServiceMsg{IfEntry: &entry}); werr != nil {
					return werr
				}
			}
			_ = safeSend(ServiceMsg{IfSnapDone: true})

		case "eventlog-snapshot":
			// One-shot: stream Windows Event Log network entries (last 24 h) and signal completion.
			// Runs in a goroutine because the Security log query can be slow.
			go func() {
				for _, e := range netinfo.ReadNetworkEventLog(24) {
					entry := e
					if werr := safeSend(ServiceMsg{EventLogEntry: &entry}); werr != nil {
						return
					}
				}
				_ = safeSend(ServiceMsg{EventLogSnapDone: true})
			}()

		case "wake":
			// Send a Wake-on-LAN magic packet to the given MAC / broadcast address.
			if cmd.WolMAC == "" {
				_ = safeSend(ServiceMsg{Err: "wake: missing MAC address"})
				continue
			}
			mac := cmd.WolMAC
			bcast := cmd.WolBroadcast
			go func() {
				parsed, err := net.ParseMAC(mac)
				if err != nil {
					_ = safeSend(ServiceMsg{WolResult: &WolResult{MAC: mac, Err: "invalid MAC: " + err.Error()}})
					return
				}
				if bcast == "" {
					bcast = "255.255.255.255"
				}
				err = SendWakeOnLAN(parsed, bcast)
				errStr := ""
				if err != nil {
					errStr = err.Error()
				}
				_ = safeSend(ServiceMsg{WolResult: &WolResult{MAC: mac, Err: errStr}})
			}()

		case "hosts-add":
			if cmd.HostsAdd == nil {
				continue
			}
			ha := cmd.HostsAdd
			asyncCacheOp("hosts-add", func() error { return netinfo.AddHostsEntry(ha.IP, ha.Hostnames) })

		case "hosts-delete":
			if cmd.Target == "" {
				continue
			}
			target := cmd.Target
			asyncCacheOp("hosts-delete", func() error { return netinfo.DeleteHostsEntry(target) })

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
				defer conn.Close()
				// Perform SOCKS5 greeting to verify the proxy actually speaks SOCKS5,
				// not just any TCP listener (e.g. SSH, HTTP).
				conn.SetDeadline(time.Now().Add(5 * time.Second)) //nolint:errcheck
				if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
					_ = safeSend(ServiceMsg{ProxyErr: "SOCKS5 handshake write: " + err.Error()})
					return
				}
				resp := make([]byte, 2)
				if _, err := io.ReadFull(conn, resp); err != nil {
					_ = safeSend(ServiceMsg{ProxyErr: "SOCKS5 handshake read: " + err.Error()})
					return
				}
				if resp[0] != 0x05 {
					_ = safeSend(ServiceMsg{ProxyErr: fmt.Sprintf("not a SOCKS5 server (got 0x%02X 0x%02X)", resp[0], resp[1])})
					return
				}
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
