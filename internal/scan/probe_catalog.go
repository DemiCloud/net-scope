package scan

import "context"

// ---------------------------------------------------------------------------
// Deep probe catalog
//
// A "deep probe" is an on-demand, protocol-aware inspection that streams
// structured output back to the GUI line-by-line via ProbeEvent messages.
// Deep probes are distinct from the simple banner-grab probes in probe.go:
//
//   Simple probes (probe.go / RunProbe)
//     - Fast banner grabs used during scans (SSH, HTTP, HTTPS, …)
//     - Return a single ProbeResult string
//     - No streaming
//
//   Deep probes (this file / internal/probes/)
//     - Protocol-aware exchanges: SMB NEGOTIATE, Redis PING, LDAP RootDSE, …
//     - Emit multiple ProbeEvent lines while running
//     - Return []Observation that are merged into the session service registry
//     - Registered at startup via RegisterDeepProbe; looked up by ExtProbeID
// ---------------------------------------------------------------------------

// DeepProbeRunner is the function signature all deep probes must implement.
//
//   ctx   – cancelled when the parent service connection closes or the user stops the run.
//   ip    – target IP address string (never a hostname).
//   port  – target port, already resolved from ProbeSpec.Port or DeepProbe.DefaultPort.
//   dial  – optional SOCKS5 proxy dial function; nil means direct connection.
//   emit  – called with each human-readable output line as the probe executes.
//
// The probe should call emit() for every significant step so the GUI stays
// responsive during slow or multi-step exchanges. Returned observations are
// merged into the session service registry for this IP:port.
type DeepProbeRunner func(ctx context.Context, ip string, port int, dial DialFunc, emit func(string)) ([]Observation, error)

// DeepProbe describes a registered named deep probe.
type DeepProbe struct {
	ID          string          // stable wire ID used in ProbeSpec.ExtProbeID ("smb", "redis", …)
	Group       string          // display group: "Database", "Remote Access", …
	Name        string          // human-readable label: "SMB Negotiate", "Redis PING", …
	DefaultPort int             // pre-fills the Port field in the probe dialog (editable)
	Transport   string          // "TCP" or "UDP"
	Run         DeepProbeRunner // implementation; must not be nil when registered
}

var deepProbeRegistry []DeepProbe

// RegisterDeepProbe adds p to the global registry.
// Must be called before any service connection is accepted (at startup).
func RegisterDeepProbe(p DeepProbe) {
	deepProbeRegistry = append(deepProbeRegistry, p)
}

// AllDeepProbes returns a snapshot of all registered probes in registration order.
func AllDeepProbes() []DeepProbe {
	out := make([]DeepProbe, len(deepProbeRegistry))
	copy(out, deepProbeRegistry)
	return out
}

// DeepProbeByID returns the first registered probe with the given stable ID.
func DeepProbeByID(id string) (DeepProbe, bool) {
	for _, p := range deepProbeRegistry {
		if p.ID == id {
			return p, true
		}
	}
	return DeepProbe{}, false
}

// ProbeEvent is a streaming message emitted by a deep probe run.
// The GUI dialog receives one ProbeEvent per emit() call, then a final
// ProbeEvent with Done=true when the probe completes.
type ProbeEvent struct {
	RunID string `json:"run_id"`         // echoed from ProbeSpec.RunID; routes to the correct dialog
	Text  string `json:"text,omitempty"` // one output line; empty on the Done-only final event
	Done  bool   `json:"done,omitempty"` // true on the final event for this run
	Err   string `json:"err,omitempty"`  // set on the Done event when the probe returned an error
}
