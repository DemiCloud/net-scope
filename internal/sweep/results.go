package sweep

import (
	"fmt"
	"net"
	"strings"
	"time"
)

// SNMPInfo holds device identity fields retrieved via SNMP.
type SNMPInfo struct {
	SysDescr    string // often contains model number and firmware version
	SysName     string
	SysLocation string
	SysContact  string
}

// ServiceInfo describes a service or device discovered via broadcast protocols.
type ServiceInfo struct {
	Source  string   // "mdns", "ssdp"
	Name    string   // instance/device name
	Type    string   // service type (e.g. "_http._tcp", "urn:schemas-upnp-org:device:...")
	Details []string // TXT records, SSDP headers, etc.
}

// Result holds everything discovered about a single host.
type Result struct {
	IP          net.IP
	Alive       bool
	MAC         net.HardwareAddr
	Vendor      string // OUI vendor from MAC
	OpenPorts   []int
	Hostname    string
	NetBIOS     string    // NetBIOS workstation name (Windows hosts)
	Latency     time.Duration
	TTL         uint8     // ICMP TTL as received (0 = unknown)
	OS          OSHint    // best-guess OS
	Banner      BannerInfo // per-port service banners
	SNMP        *SNMPInfo
	Services    []ServiceInfo // mDNS, SSDP discoveries
}

// String returns a human-readable summary of the result.
func (r Result) String() string {
	if !r.Alive {
		return fmt.Sprintf("%s\tdown", r.IP)
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
