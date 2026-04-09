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
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// Wire types — GUI ↔ service (newline-delimited JSON over TLS localhost)
// ---------------------------------------------------------------------------

// ServiceCmd is sent by the GUI to the service.
type ServiceCmd struct {
	// Cmd is one of: "scan", "stop", "probe", "dhcp-start", "dhcp-stop", "shutdown"
	Cmd        string     `json:"cmd"`
	Target     string     `json:"target,omitempty"`
	Config     *Config    `json:"config,omitempty"`
	// ScanID is echoed back in every Result and Done message for this scan.
	// The GUI uses it to discard results from superseded scans.
	ScanID     uint64     `json:"scan_id,omitempty"`
	// Probe is set for the "probe" command.
	Probe      *ProbeSpec `json:"probe,omitempty"`
	// SOCKSProxy is the SOCKS5 address to use for the probe (empty = direct).
	SOCKSProxy string     `json:"socks_proxy,omitempty"`
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

	var scanCancel context.CancelFunc
	var dhcpCancel context.CancelFunc

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

			sc := NewScanner(*cmd.Config)
			ch, err := sc.Scan(ctx, cmd.Target)
			if err != nil {
				scanCancel()
				scanCancel = nil
				_ = safeSend(ServiceMsg{Err: "scan: " + err.Error(), ScanID: scanID})
				continue
			}
			// Stream results in a goroutine so the command loop stays responsive.
			go func() {
				for r := range ch {
					rCopy := r
					if werr := safeSend(ServiceMsg{Result: &rCopy, ScanID: scanID}); werr != nil {
						return
					}
				}
				_ = safeSend(ServiceMsg{Done: true, Stats: &sc.Stats, ScanID: scanID})
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
			}

		case "shutdown":
			if scanCancel != nil {
				scanCancel()
			}
			if dhcpCancel != nil {
				dhcpCancel()
			}
			return nil

		default:
			_ = safeSend(ServiceMsg{Err: "unknown command: " + cmd.Cmd})
		}
	}
}
