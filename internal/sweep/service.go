package sweep

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
	// Cmd is one of: "scan", "stop", "shutdown"
	Cmd    string  `json:"cmd"`
	Target string  `json:"target,omitempty"`
	Config *Config `json:"config,omitempty"`
}

// ServiceMsg is sent by the service to the GUI.
// Exactly one of Ready/Result/Done/Err is meaningful per message.
type ServiceMsg struct {
	// Ready is sent once after connection is established.
	// Elevated reports whether the service process is running as admin.
	Ready    bool       `json:"ready,omitempty"`
	Elevated bool       `json:"elevated,omitempty"`
	// Result carries a single scanned host.
	Result   *Result    `json:"result,omitempty"`
	// Done marks end of a scan; Stats is populated.
	Done     bool       `json:"done,omitempty"`
	Stats    *ScanStats `json:"stats,omitempty"`
	// Err carries a human-readable error string.
	Err      string     `json:"err,omitempty"`
}

// ---------------------------------------------------------------------------
// Service — runs inside the elevated (or user-level) subprocess
// ---------------------------------------------------------------------------

// RunServiceConn is the main loop run by the service subprocess.
// It handles multiple sequential scan commands over a single connection,
// staying alive until the GUI sends "shutdown" or closes the connection.
func RunServiceConn(conn net.Conn) error {
	defer conn.Close()

	dec := json.NewDecoder(conn)
	enc := json.NewEncoder(conn)

	// Announce readiness and our elevation state.
	if err := enc.Encode(ServiceMsg{Ready: true, Elevated: IsElevated()}); err != nil {
		return fmt.Errorf("service ready: %w", err)
	}

	var scanCancel context.CancelFunc

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

		case "shutdown":
			return nil

		default:
			_ = enc.Encode(ServiceMsg{Err: "unknown command: " + cmd.Cmd})
		}
	}
}
