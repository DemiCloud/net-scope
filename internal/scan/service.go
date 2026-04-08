package scan

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
)

// ---------------------------------------------------------------------------
// Wire types — GUI ↔ service (newline-delimited JSON over TCP localhost)
// ---------------------------------------------------------------------------

// ServiceCmd is sent by the GUI to the service.
type ServiceCmd struct {
	// Cmd is one of: "scan", "stop", "dhcp-start", "dhcp-stop", "shutdown"
	Cmd    string  `json:"cmd"`
	Target string  `json:"target,omitempty"`
	Config *Config `json:"config,omitempty"`
}

// ServiceMsg is sent by the service to the GUI.
// Exactly one of Ready/Result/Done/DHCP/Err is meaningful per message.
type ServiceMsg struct {
	// Ready is sent once after connection is established.
	// Elevated reports whether the service process is running as admin.
	// Token echoes back the secret passed via --service-token so the client
	// can verify it connected to its own subprocess (not a hijacker).
	Ready    bool        `json:"ready,omitempty"`
	Elevated bool        `json:"elevated,omitempty"`
	Token    string      `json:"token,omitempty"`
	// Result carries a single scanned host.
	Result   *Result     `json:"result,omitempty"`
	// Done marks end of a scan; Stats is populated.
	Done     bool        `json:"done,omitempty"`
	Stats    *ScanStats  `json:"stats,omitempty"`
	// DHCP carries a single passively-observed DHCP packet.
	DHCP     *DHCPEvent  `json:"dhcp,omitempty"`
	// Err carries a human-readable error string.
	Err      string      `json:"err,omitempty"`
}

// ---------------------------------------------------------------------------
// Service — runs inside the elevated (or user-level) subprocess
// ---------------------------------------------------------------------------

// RunServiceConn is the main loop run by the service subprocess.
// It handles multiple sequential scan commands over a single connection,
// staying alive until the GUI sends "shutdown" or closes the connection.
// token is the hex secret passed via --service-token; it is echoed in the
// Ready handshake so the client can verify it connected to its own subprocess.
func RunServiceConn(conn net.Conn, token string) error {
	defer conn.Close()

	dec := json.NewDecoder(conn)
	enc := json.NewEncoder(conn)

	// Announce readiness, elevation state, and echo the auth token.
	if err := enc.Encode(ServiceMsg{Ready: true, Elevated: IsElevated(), Token: token}); err != nil {
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
				_ = enc.Encode(ServiceMsg{Err: "scan: missing target or config"})
				continue
			}
			ctx, cancel := context.WithCancel(context.Background())
			scanCancel = cancel

			sc := NewScanner(*cmd.Config)
			ch, err := sc.Scan(ctx, cmd.Target)
			if err != nil {
				scanCancel()
				scanCancel = nil
				_ = enc.Encode(ServiceMsg{Err: "scan: " + err.Error()})
				continue
			}
			for r := range ch {
				rCopy := r
				if werr := enc.Encode(ServiceMsg{Result: &rCopy}); werr != nil {
					return werr
				}
			}
			scanCancel = nil
			if werr := enc.Encode(ServiceMsg{Done: true, Stats: &sc.Stats}); werr != nil {
				return werr
			}

		case "stop":
			if scanCancel != nil {
				scanCancel()
				scanCancel = nil
			}

		case "dhcp-start":
			if dhcpCancel != nil {
				break // already running
			}
			if !IsElevated() {
				_ = enc.Encode(ServiceMsg{Err: "dhcp-start: requires elevation"})
				continue
			}
			ctx, cancel := context.WithCancel(context.Background())
			dhcpCancel = cancel
			ch := make(chan DHCPEvent, 64)
			if err := ListenDHCP(ctx, ch); err != nil {
				dhcpCancel()
				dhcpCancel = nil
				_ = enc.Encode(ServiceMsg{Err: "dhcp-start: " + err.Error()})
				continue
			}
			go func() {
				for evt := range ch {
					e := evt
					if werr := enc.Encode(ServiceMsg{DHCP: &e}); werr != nil {
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
			if dhcpCancel != nil {
				dhcpCancel()
			}
			return nil

		default:
			_ = enc.Encode(ServiceMsg{Err: "unknown command: " + cmd.Cmd})
		}
	}
}
