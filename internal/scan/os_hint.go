package scan

import (
	"strings"
)

// OSHint is a best-guess operating system hint derived from passive signals:
// ICMP TTL, SSH banner, HTTP headers, SSDP/mDNS service types.
// It is intentionally coarse — "Windows", "Linux", "macOS", "Network", etc.
type OSHint string

const (
	OSWindows OSHint = "Windows"
	OSLinux   OSHint = "Linux"
	OSMacOS   OSHint = "macOS"
	OSNetwork OSHint = "Network Device"
	OSUnknown OSHint = ""
)

// guessOS combines several passive signals to guess the host OS.
// icmpTTL is the TTL observed (0 if unknown). banner is the banner grab
// result. services is the list of mDNS/SSDP services. snmp is optional.
// ports is the list of open TCP ports (nil or empty if unknown).
// vendor is the OUI vendor string from the MAC address (empty if unknown).
func guessOS(icmpTTL uint8, banner BannerInfo, services []ServiceInfo, snmp *SNMPInfo, ports []int, vendor string) OSHint {
	// ---------- SNMP sysDescr — highest confidence ----------
	if snmp != nil && snmp.SysDescr != "" {
		d := strings.ToLower(snmp.SysDescr)
		switch {
		case strings.Contains(d, "windows"):
			return OSWindows
		case strings.Contains(d, "linux"):
			return OSLinux
		case strings.Contains(d, "ios") && !strings.Contains(d, "iphone"):
			return OSNetwork // Cisco IOS
		case strings.Contains(d, "junos"):
			return OSNetwork
		case strings.Contains(d, "freebsd"), strings.Contains(d, "netbsd"),
			strings.Contains(d, "openbsd"):
			return OSLinux // close enough
		case strings.Contains(d, "darwin"), strings.Contains(d, "mac os"):
			return OSMacOS
		}
	}

	// ---------- Vendor OUI ----------
	if vendor != "" {
		v := strings.ToLower(vendor)
		switch {
		case strings.HasPrefix(v, "apple"):
			return OSMacOS
		case strings.Contains(v, "raspberry pi"):
			return OSLinux
		case strings.Contains(v, "cisco"), strings.Contains(v, "juniper"),
			strings.Contains(v, "ubiquiti"), strings.Contains(v, "mikrotik"),
			strings.Contains(v, "unifi"), strings.Contains(v, "aruba"),
			strings.Contains(v, "fortinet"), strings.Contains(v, "palo alto"):
			return OSNetwork
		}
	}

	// ---------- Open-port fingerprint ----------
	if len(ports) > 0 {
		has445 := portIn(ports, 445)
		has139 := portIn(ports, 139)
		has3389 := portIn(ports, 3389)
		has22 := portIn(ports, 22)
		has23 := portIn(ports, 23)
		has161 := portIn(ports, 161)
		has548 := portIn(ports, 548)   // AFP — Apple Filing Protocol
		has8291 := portIn(ports, 8291) // MikroTik Winbox
		has8728 := portIn(ports, 8728) // MikroTik API
		has179 := portIn(ports, 179)   // BGP
		has830 := portIn(ports, 830)   // NETCONF
		switch {
		case has445 || has139 || has3389:
			return OSWindows
		case has548:
			return OSMacOS
		case has8291 || has8728 || has179 || has830:
			return OSNetwork
		case has22 && !has445 && !has139:
			return OSLinux
		case (has23 || has161) && !has22 && !has445 && !has139:
			return OSNetwork
		}
	}

	// ---------- SSH banner ----------
	if banner.SSH != "" {
		lower := strings.ToLower(banner.SSH)
		switch {
		case strings.Contains(lower, "ubuntu"), strings.Contains(lower, "debian"),
			strings.Contains(lower, "fedora"), strings.Contains(lower, "centos"),
			strings.Contains(lower, "rhel"), strings.Contains(lower, "arch"):
			return OSLinux
		case strings.Contains(lower, "windows"):
			return OSWindows
		case strings.Contains(lower, "freebsd"), strings.Contains(lower, "netbsd"),
			strings.Contains(lower, "openbsd"):
			return OSLinux
		default:
			return OSLinux // SSH on non-Windows is almost universally Linux/BSD
		}
	}

	// ---------- HTTP Server header ----------
	for _, hdr := range []string{banner.HTTP, banner.HTTPS} {
		if hdr == "" {
			continue
		}
		lower := strings.ToLower(hdr)
		switch {
		case strings.Contains(lower, "microsoft-iis"), strings.Contains(lower, "microsoft-httpapi"), strings.Contains(lower, "microsoft httpapi"):
			return OSWindows
		case strings.Contains(lower, "apache"), strings.Contains(lower, "nginx"),
			strings.Contains(lower, "lighttpd"), strings.Contains(lower, "caddy"):
			return OSLinux
		case strings.Contains(lower, "jetty"), strings.Contains(lower, "tomcat"):
			return OSLinux
		}
	}

	// ---------- mDNS / SSDP service types ----------
	for _, svc := range services {
		t := strings.ToLower(svc.Type)
		n := strings.ToLower(svc.Name + " " + strings.Join(svc.Details, " "))
		switch {
		case strings.Contains(t, "_airplay"), strings.Contains(t, "_raop"),
			strings.Contains(t, "_afp"), strings.Contains(t, "_device-info"),
			strings.Contains(n, "apple"):
			return OSMacOS
		case strings.Contains(t, "_workstation") || strings.Contains(n, "linux"):
			return OSLinux
		case strings.Contains(t, "windows") || strings.Contains(n, "windows"):
			return OSWindows
		case strings.Contains(n, "cisco") || strings.Contains(n, "juniper") ||
			strings.Contains(n, "mikrotik") || strings.Contains(n, "ubiquiti") ||
			strings.Contains(n, "unifi"):
			return OSNetwork
		}
	}

	// ---------- ICMP TTL heuristic (last resort) ----------
	// Windows default: 128; Linux/macOS: 64; network gear: 255
	switch {
	case icmpTTL >= 120 && icmpTTL <= 130:
		return OSWindows
	case icmpTTL >= 60 && icmpTTL <= 70:
		return OSLinux
	case icmpTTL >= 250:
		return OSNetwork
	}

	return OSUnknown
}

// portIn reports whether port p appears in the sorted or unsorted slice ports.
func portIn(ports []int, p int) bool {
	for _, v := range ports {
		if v == p {
			return true
		}
	}
	return false
}
