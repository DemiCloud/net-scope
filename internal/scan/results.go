package scan

import (
	"fmt"
	"net"
	"strings"
	"time"
)

// SNMPInfo holds device identity fields retrieved via SNMP.
type SNMPInfo struct {	SysDescr    string // often contains model number and firmware version
	SysName     string
	SysLocation string
	SysContact  string
}

// SYNProbeInfo holds TCP stack fingerprint data extracted from a SYN-ACK.
// WindowSize and Options are zero/empty when the probe could not be performed
// (no raw socket privilege on Linux, always on Windows, no open ports found).
type SYNProbeInfo struct {
	WindowSize uint16 // initial advertised receive window
	Options    string // options in order, e.g. "MSS(1460) SACK TS NOP WScale(7)"
}

// ServiceInfo describes a service or device discovered via broadcast protocols.
type ServiceInfo struct {
	Source  string   // "mdns", "ssdp"
	Name    string   // instance/device name
	Type    string   // service type (e.g. "_http._tcp", "urn:schemas-upnp-org:device:...")
	Details []string // TXT records, SSDP headers, etc.
}

// PortService describes a network service identified on a specific TCP port.
// Product and Version are best-effort extractions from banner text and protocol
// headers; Confidence reflects how reliable that identification is (0–100).
type PortService struct {
	Port       int    // TCP port number
	Product    string // e.g. "OpenSSH", "nginx", "Microsoft IIS"
	Version    string // e.g. "9.3p2", "1.27.4" (empty if unknown)
	Banner     string // raw banner or Server: header captured from this port
	TLSCert    string // TLS cert descriptor ("SubjectCN (IssuerOrg)"), empty if no TLS
	ALPN       string // ALPN protocol negotiated during TLS handshake ("h2", "http/1.1")
	Confidence uint8  // 0–100: how confident we are in the Product identification
}

// Result holds everything discovered about a single host.
type Result struct {
	IP          net.IP
	Alive       bool
	// Partial is true when only liveness data is available (phase 1 discovery);
	// deepProbe has not yet run. A subsequent Result for the same IP with
	// Partial: false replaces this one.
	Partial      bool
	MAC          net.HardwareAddr
	Vendor       string // OUI vendor from MAC
	OpenPorts    []int
	Hostname     string
	NetBIOS      string        // NetBIOS workstation name (Windows hosts)
	Latency      time.Duration
	TTL          uint8         // ICMP TTL as received (0 = unknown)
	OS           OSHint        // best-guess OS
	OSConfidence uint8         // 0–100; 0 = no signal reached minimum threshold
	Banner       BannerInfo    // per-port service banners (derived from PortServices)
	PortServices []PortService // per-port service identification (populated when BannerGrab is on)
	SNMP         *SNMPInfo
	SYNProbe     SYNProbeInfo  // TCP stack fingerprint from SYN-ACK (elevation-gated)
	Services     []ServiceInfo // mDNS, SSDP discoveries
}

// String returns a human-readable summary of the result.
func (r Result) String() string {
	if !r.Alive {
		return fmt.Sprintf("%s\tdown", r.IP)
	}

	if r.Partial {
		mac := "-"
		if r.MAC != nil {
			mac = r.MAC.String()
		}
		vendor := r.Vendor
		if vendor == "" {
			vendor = "-"
		}
		return fmt.Sprintf("%s\t(discovering)\t%s\t%s\t-\t-\t%s",
			r.IP, mac, vendor, r.Latency.Round(time.Millisecond))
	}

	mac := "-"
	if r.MAC != nil {
		mac = r.MAC.String()
	}
	vendor := r.Vendor
	if vendor == "" {
		vendor = "-"
	}
	hostname := r.Hostname
	if hostname == "" && r.NetBIOS != "" {
		hostname = r.NetBIOS
	}
	if hostname == "" {
		hostname = "-"
	}

	ports := make([]string, len(r.OpenPorts))
	for i, p := range r.OpenPorts {
		ports[i] = fmt.Sprintf("%d", p)
	}
	portStr := "-"
	if len(ports) > 0 {
		portStr = strings.Join(ports, ",")
	}

	osStr := string(r.OS)
	if osStr == "" {
		osStr = "-"
	}

	line := fmt.Sprintf("%s\t%s\t%s\t%s\t%s\t%s\t%s",
		r.IP, hostname, mac, vendor, portStr, osStr,
		r.Latency.Round(time.Millisecond))

	if r.SNMP != nil && r.SNMP.SysDescr != "" {
		line += "\t" + r.SNMP.SysDescr
	}

	// Append banner info if available
	for _, b := range []struct{ label, val string }{
		{"SSH", r.Banner.SSH}, {"FTP", r.Banner.FTP},
		{"HTTP", r.Banner.HTTP}, {"HTTPS", r.Banner.HTTPS},
		{"SMTP", r.Banner.SMTP}, {"Telnet", r.Banner.Telnet},
	} {
		if b.val != "" {
			line += fmt.Sprintf("\t[%s] %s", b.label, b.val)
		}
	}

	for _, svc := range r.Services {
		line += fmt.Sprintf("\t[%s] %s (%s)", svc.Source, svc.Name, svc.Type)
	}

	return line
}
