package scan

import (
	"strings"
)

// OSHint is a best-guess operating system hint derived from passive signals:
// ICMP TTL, SSH banner, HTTP headers, SSDP/mDNS service types.
// It is intentionally coarse — "Windows", "Linux", "macOS", "Network", etc.
type OSHint string

const (
	OSWindows  OSHint = "Windows"
	OSLinux    OSHint = "Linux"
	OSMacOS    OSHint = "macOS"
	OSNetwork  OSHint = "Network Device"
	OSRouterOS OSHint = "RouterOS"
	OSCiscoIOS OSHint = "Cisco IOS"
	OSJunOS    OSHint = "JunOS"
	OSUbiquiti OSHint = "Ubiquiti"
	OSAruba    OSHint = "Aruba"
	OSFortinet OSHint = "Fortinet"
	OSUnknown  OSHint = ""
)

// Weights for individual OS detection signals.
// Score per OS = max(weights) + min((n−1)×5, 15) where n = number of
// signals voting for it. Corroborating signals nudge confidence up without
// letting many weak signals beat a single authoritative one.
const (
	wSNMP        = 90 // SNMP sysDescr: direct OS self-identification
	wSSHRouterOS = 90 // SSH-2.0-ROSSSH: proprietary, as reliable as SNMP
	wSSHSpecific = 85 // SSH banner naming a distro or vendor
	wHTTPVendor  = 75 // Microsoft-IIS / HTTPAPI
	wOUI         = 75 // MAC OUI vendor mapping
	wMDNS        = 65 // mDNS / SSDP service type or name
	wSYN         = 55 // TCP SYN-ACK initial window fingerprint
	wHTTPGeneric = 50 // Apache / nginx (runs on any OS)
	wSSHGeneric  = 40 // SSH present but no distro/vendor info → probably Linux
	wTTL         = 30 // ICMP TTL heuristic (last resort)

	// Minimum total score required to report a guess.
	minScore = 25
	// Maximum bonus from corroborating signals across tiers.
	maxBonus = 15
)

// guessOS combines passive signals to guess the host OS and returns a
// confidence score 0–100 (0 = no signal reached the minimum threshold).
// icmpTTL is the TTL observed (0 if unknown). banner is the banner grab
// result. services is the list of mDNS/SSDP services. snmp is optional.
// vendor is the OUI vendor string from the MAC address (empty if unknown).
// syn holds the TCP SYN-ACK window and options (zero when unavailable).
func guessOS(icmpTTL uint8, banner BannerInfo, services []ServiceInfo, snmp *SNMPInfo, vendor string, syn SYNProbeInfo) (OSHint, uint8) {
	allVotes := make(map[OSHint][]int)
	vote := func(hint OSHint, weight int) {
		if hint != OSUnknown {
			allVotes[hint] = append(allVotes[hint], weight)
		}
	}

	// ---------- SNMP sysDescr — highest confidence ----------
	if snmp != nil && snmp.SysDescr != "" {
		d := strings.ToLower(snmp.SysDescr)
		switch {
		case strings.Contains(d, "windows"):
			vote(OSWindows, wSNMP)
		case strings.Contains(d, "routeros"):
			vote(OSRouterOS, wSNMP)
		case strings.Contains(d, "linux"):
			vote(OSLinux, wSNMP)
		case strings.Contains(d, "ios") && !strings.Contains(d, "iphone"):
			vote(OSCiscoIOS, wSNMP)
		case strings.Contains(d, "junos"):
			vote(OSJunOS, wSNMP)
		case strings.Contains(d, "freebsd"), strings.Contains(d, "netbsd"),
			strings.Contains(d, "openbsd"):
			vote(OSLinux, wSNMP)
		case strings.Contains(d, "darwin"), strings.Contains(d, "mac os"):
			vote(OSMacOS, wSNMP)
		}
	}

	// ---------- Vendor OUI ----------
	if vendor != "" {
		v := strings.ToLower(vendor)
		switch {
		case strings.HasPrefix(v, "apple"):
			vote(OSMacOS, wOUI)
		case strings.Contains(v, "raspberry pi"):
			vote(OSLinux, wOUI)
		case strings.Contains(v, "mikrotik"):
			vote(OSRouterOS, wOUI)
		case strings.Contains(v, "cisco"):
			vote(OSCiscoIOS, wOUI)
		case strings.Contains(v, "juniper"):
			vote(OSJunOS, wOUI)
		case strings.Contains(v, "ubiquiti"), strings.Contains(v, "unifi"):
			vote(OSUbiquiti, wOUI)
		case strings.Contains(v, "aruba"):
			vote(OSAruba, wOUI)
		case strings.Contains(v, "fortinet"):
			vote(OSFortinet, wOUI)
		case strings.Contains(v, "palo alto"):
			vote(OSNetwork, wOUI)
		}
	}

	// ---------- SSH banner ----------
	// Application-layer banners are more specific than TCP stack signals.
	if banner.SSH != "" {
		lower := strings.ToLower(banner.SSH)
		switch {
		case strings.Contains(lower, "rosssh"):
			vote(OSRouterOS, wSSHRouterOS)
		case strings.HasPrefix(lower, "ssh-2.0-cisco"):
			vote(OSCiscoIOS, wSSHSpecific)
		case strings.Contains(lower, "windows"):
			vote(OSWindows, wSSHSpecific)
		case strings.Contains(lower, "ubuntu"), strings.Contains(lower, "debian"),
			strings.Contains(lower, "fedora"), strings.Contains(lower, "centos"),
			strings.Contains(lower, "rhel"), strings.Contains(lower, "arch"):
			vote(OSLinux, wSSHSpecific)
		case strings.Contains(lower, "freebsd"), strings.Contains(lower, "netbsd"),
			strings.Contains(lower, "openbsd"):
			vote(OSLinux, wSSHSpecific)
		default:
			vote(OSLinux, wSSHGeneric) // SSH on non-Windows is almost universally Linux/BSD
		}
	}

	// ---------- TCP SYN-ACK window + options ----------
	// Well-known initial window sizes are highly OS-specific.
	// Linux 3.12+ default: 29200; Windows 10/11: 64240; macOS: 65535+timestamps.
	if syn.WindowSize > 0 {
		hasTS := strings.Contains(syn.Options, "TS")
		switch {
		case syn.WindowSize == 64240:
			vote(OSWindows, wSYN)
		case syn.WindowSize == 29200:
			vote(OSLinux, wSYN)
		case syn.WindowSize == 65535 && hasTS:
			vote(OSMacOS, wSYN)
		}
	}

	// ---------- HTTP Server header ----------
	for _, hdr := range []string{banner.HTTP, banner.HTTPS} {
		if hdr == "" {
			continue
		}
		lower := strings.ToLower(hdr)
		switch {
		case strings.Contains(lower, "microsoft-iis"),
			strings.Contains(lower, "microsoft-httpapi"),
			strings.Contains(lower, "microsoft httpapi"):
			vote(OSWindows, wHTTPVendor)
		case strings.Contains(lower, "apache"), strings.Contains(lower, "nginx"),
			strings.Contains(lower, "lighttpd"), strings.Contains(lower, "caddy"):
			vote(OSLinux, wHTTPGeneric)
		case strings.Contains(lower, "jetty"), strings.Contains(lower, "tomcat"):
			vote(OSLinux, wHTTPGeneric)
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
			vote(OSMacOS, wMDNS)
		case strings.Contains(t, "_workstation") || strings.Contains(n, "linux"):
			vote(OSLinux, wMDNS)
		case strings.Contains(t, "windows") || strings.Contains(n, "windows"):
			vote(OSWindows, wMDNS)
		case strings.Contains(n, "mikrotik"):
			vote(OSRouterOS, wMDNS)
		case strings.Contains(n, "cisco"):
			vote(OSCiscoIOS, wMDNS)
		case strings.Contains(n, "juniper"):
			vote(OSJunOS, wMDNS)
		case strings.Contains(n, "ubiquiti") || strings.Contains(n, "unifi"):
			vote(OSUbiquiti, wMDNS)
		}
	}

	// ---------- ICMP TTL heuristic (last resort) ----------
	// Windows default: 128; Linux/macOS: 64; network gear: 255
	switch {
	case icmpTTL >= 120 && icmpTTL <= 130:
		vote(OSWindows, wTTL)
	case icmpTTL >= 60 && icmpTTL <= 70:
		vote(OSLinux, wTTL)
	case icmpTTL >= 250:
		vote(OSNetwork, wTTL)
	}

	// ---------- Tally votes ----------
	winner, best := OSUnknown, 0
	for hint, weights := range allVotes {
		maxW := 0
		for _, w := range weights {
			if w > maxW {
				maxW = w
			}
		}
		bonus := (len(weights) - 1) * 5
		if bonus > maxBonus {
			bonus = maxBonus
		}
		score := maxW + bonus
		if score > best {
			best = score
			winner = hint
		}
	}

	if best < minScore {
		return OSUnknown, 0
	}
	conf := uint8(best)
	if best > 100 {
		conf = 100
	}
	return winner, conf
}


