package sweep

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
)

// ProbeResult is a single line written by the probe server to the connection.
// Either Result is set (a scanned host) or Done is true (final stats line).
type ProbeResult struct {
	Done   bool       `json:"done,omitempty"`
	Stats  *ScanStats `json:"stats,omitempty"`
	Result *Result    `json:"result,omitempty"`
}

// ProbeRequest is the JSON object sent by the GUI to start a probe session.
type ProbeRequest struct {
	Target string `json:"target"`
	Config Config `json:"config"`
}

// RunProbeServer accepts one connection on ln, reads a ProbeRequest, runs the
// scan, and streams ProbeResult lines back. Exits when the scan completes or
// the connection is closed. Intended to be called from the elevated subprocess.
func RunProbeServer(ln net.Listener) error {
	conn, err := ln.Accept()
	if err != nil {
		return fmt.Errorf("probe accept: %w", err)
	}
	ln.Close()
	return RunProbeConn(conn)
}

// RunProbeConn runs the probe server on an already-established connection.
// The elevated subprocess uses this after dialling the GUI's listener.
func RunProbeConn(conn net.Conn) error {
	defer conn.Close()

	dec := json.NewDecoder(conn)
	enc := json.NewEncoder(conn)

	var req ProbeRequest
	if err := dec.Decode(&req); err != nil {
		return fmt.Errorf("probe decode request: %w", err)
	}

	sc := NewScanner(req.Config)
	ch, err := sc.Scan(context.Background(), req.Target)
	if err != nil {
		return fmt.Errorf("probe scan: %w", err)
	}

	for r := range ch {
		rCopy := r
		if werr := enc.Encode(ProbeResult{Result: &rCopy}); werr != nil {
			return werr
		}
	}

	return enc.Encode(ProbeResult{Done: true, Stats: &sc.Stats})
}
