// Package guigio — sensor service IPC client.
//
// This file has ZERO GUI framework imports and ZERO platform-specific imports.
// It may be imported by any front-end (Gio, TUI, CLI, tests) without pulling
// in windowing or rendering dependencies.
//
// Security model:
//   - The GUI generates a 32-byte cryptographically random token at startup.
//   - The token is passed to the child process as --service-token=<hex>.
//   - On connect the service echoes the token back in the Ready handshake.
//   - The client rejects any connection whose token does not match, preventing
//     a local process from hijacking the socket by racing the accept.
//   - The listener binds to 127.0.0.1:<random-port>; the port is advertised
//     only via the child argv, so no unauthenticated process can find it by
//     scanning loopback alone without also knowing the token.
package guigio

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"sync"
	"time"

	"github.com/demicloud/net-scope/internal/scan"
)

// ServiceEvent carries a single message arriving from the sensor service.
// Exactly one field is meaningful per event.
type ServiceEvent struct {
	Ready    bool            // initial handshake confirmed
	Elevated bool            // service is running as root/admin
	Result   *scan.Result    // a scan result
	DHCP     *scan.DHCPEvent // a DHCP passive event
	Stats    *scan.ScanStats // scan complete + stats
	Done     bool            // scan finished (Stats is set)
	Err      string          // fatal error from service
}

// ServiceClient manages one sensor service subprocess and its IPC connection.
// All exported methods are safe to call from any goroutine.
type ServiceClient struct {
	mu       sync.Mutex
	conn     net.Conn
	enc      *json.Encoder
	dec      *json.Decoder
	encMu    sync.Mutex // serialises Encode calls
	decMu    sync.Mutex // serialises Decode calls (scan response stream)
	elevated bool
	token    string // hex-encoded 32-byte secret
}

// NewServiceClient returns an uninitialised client. Call Start to connect.
func NewServiceClient() *ServiceClient {
	return &ServiceClient{}
}

// IsRunning reports whether a live service connection is open.
func (c *ServiceClient) IsRunning() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.conn != nil
}

// IsElevated reports whether the connected service process is running as admin/root.
func (c *ServiceClient) IsElevated() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.elevated
}

// Start spawns a sensor service subprocess and connects to it.
// If elevated is true the subprocess is launched with privilege escalation
// (pkexec on Linux, ShellExecuteEx "runas" on Windows — handled by
// spawnServiceProcess which is platform-specific).
// events receives all messages from the service until the connection closes.
// Start returns once the Ready handshake is received (or on error).
func (c *ServiceClient) Start(elevated bool, events chan<- ServiceEvent) error {
	// Generate a fresh token for this session.
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return fmt.Errorf("service token: %w", err)
	}
	token := hex.EncodeToString(raw)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("service listener: %w", err)
	}
	addr := ln.Addr().String()

	if err := spawnServiceProcess(addr, token, elevated); err != nil {
		ln.Close()
		return fmt.Errorf("spawn service: %w", err)
	}

	// Accept with a generous timeout — service subprocess startup can be slow
	// when elevation dialogs appear.
	ln.(*net.TCPListener).SetDeadline(time.Now().Add(90 * time.Second))
	conn, err := ln.Accept()
	ln.Close()
	if err != nil {
		return fmt.Errorf("service accept: %w", err)
	}

	dec := json.NewDecoder(conn)
	enc := json.NewEncoder(conn)

	// First message must be the ready handshake; validate the reflected token.
	var msg scan.ServiceMsg
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	if err := dec.Decode(&msg); err != nil {
		conn.Close()
		return fmt.Errorf("service handshake: %w", err)
	}
	conn.SetReadDeadline(time.Time{}) // clear deadline for subsequent reads

	if !msg.Ready {
		conn.Close()
		return fmt.Errorf("service handshake: unexpected first message")
	}
	if msg.Token != token {
		conn.Close()
		return fmt.Errorf("service handshake: token mismatch — possible hijack attempt")
	}

	c.mu.Lock()
	if c.conn != nil {
		c.conn.Close()
	}
	c.conn = conn
	c.enc = enc
	c.dec = dec
	c.elevated = msg.Elevated
	c.token = token
	c.mu.Unlock()

	if events != nil {
		events <- ServiceEvent{Ready: true, Elevated: msg.Elevated}
		go c.pump(conn, dec, events)
	}
	return nil
}

// Stop sends a shutdown command and tears down the connection.
func (c *ServiceClient) Stop() {
	c.mu.Lock()
	enc := c.enc
	conn := c.conn
	c.conn = nil
	c.enc = nil
	c.dec = nil
	c.elevated = false
	c.mu.Unlock()

	if enc != nil {
		c.encMu.Lock()
		_ = enc.Encode(scan.ServiceCmd{Cmd: "shutdown"})
		c.encMu.Unlock()
	}
	if conn != nil {
		conn.Close()
	}
}

// Scan sends a scan command to the service. Results arrive on the events
// channel passed to Start. gen is a caller-managed generation counter
// used to discard results from superseded scans.
func (c *ServiceClient) Scan(target string, cfg scan.Config) error {
	c.mu.Lock()
	enc := c.enc
	c.mu.Unlock()
	if enc == nil {
		return fmt.Errorf("service not running")
	}
	c.encMu.Lock()
	err := enc.Encode(scan.ServiceCmd{Cmd: "scan", Target: target, Config: &cfg})
	c.encMu.Unlock()
	return err
}

// StopScan asks the service to cancel an in-progress scan.
func (c *ServiceClient) StopScan() {
	c.mu.Lock()
	enc := c.enc
	c.mu.Unlock()
	if enc == nil {
		return
	}
	c.encMu.Lock()
	_ = enc.Encode(scan.ServiceCmd{Cmd: "stop"})
	c.encMu.Unlock()
}

// StartDHCP asks the service to begin passive DHCP capture (requires elevation).
func (c *ServiceClient) StartDHCP() error {
	c.mu.Lock()
	enc := c.enc
	c.mu.Unlock()
	if enc == nil {
		return fmt.Errorf("service not running")
	}
	c.encMu.Lock()
	err := enc.Encode(scan.ServiceCmd{Cmd: "dhcp-start"})
	c.encMu.Unlock()
	return err
}

// pump reads messages from the service and forwards them to events until the
// connection closes.
func (c *ServiceClient) pump(conn net.Conn, dec *json.Decoder, events chan<- ServiceEvent) {
	for {
		var msg scan.ServiceMsg
		c.decMu.Lock()
		err := dec.Decode(&msg)
		c.decMu.Unlock()
		if err != nil {
			// Connection closed or broken.
			c.mu.Lock()
			if c.conn == conn {
				c.conn = nil
				c.enc = nil
				c.dec = nil
				c.elevated = false
			}
			c.mu.Unlock()
			events <- ServiceEvent{Err: "service disconnected: " + err.Error()}
			return
		}
		switch {
		case msg.Err != "":
			events <- ServiceEvent{Err: msg.Err}
		case msg.Done:
			events <- ServiceEvent{Done: true, Stats: msg.Stats}
		case msg.Result != nil:
			r := *msg.Result
			events <- ServiceEvent{Result: &r}
		case msg.DHCP != nil:
			d := *msg.DHCP
			events <- ServiceEvent{DHCP: &d}
		}
	}
}

// spawnServiceProcess is implemented per-platform in:
//   service_windows.go  — ShellExecuteEx "runas" for elevated, CreateProcess for user
//   service_other.go    — exec.Command / pkexec for Linux

// defaultSpawn is the fallback used by service_other.go.
func defaultSpawn(addr, token string, elevated bool) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	args := []string{"service", addr, token}
	var cmd *exec.Cmd
	if elevated {
		// Try pkexec first (PolicyKit, available on most Linux desktops).
		// Fall back to sudo if pkexec is not found.
		pkexec, pkErr := exec.LookPath("pkexec")
		if pkErr == nil {
			cmd = exec.Command(pkexec, append([]string{exe}, args...)...)
		} else {
			cmd = exec.Command("sudo", append([]string{"-n", exe}, args...)...)
		}
	} else {
		cmd = exec.Command(exe, args...)
	}
	cmd.Stdout = nil
	cmd.Stderr = nil
	return cmd.Start()
}
