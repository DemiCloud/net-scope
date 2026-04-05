package sweep

import (
	"net"
)

// private holds all RFC1918 and link-local ranges that are considered
// "local" for the purposes of WAN safety checks.
var private = []net.IPNet{
	// RFC 1918
	parseCIDR("10.0.0.0/8"),
	parseCIDR("172.16.0.0/12"),
	parseCIDR("192.168.0.0/16"),
	// Link-local
	parseCIDR("169.254.0.0/16"),
	// IPv6 ULA / link-local
	parseCIDR("fc00::/7"),
	parseCIDR("fe80::/10"),
	// Loopback
	parseCIDR("127.0.0.0/8"),
	parseCIDR("::1/128"),
}

func parseCIDR(s string) net.IPNet {
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		panic("wan: bad built-in CIDR: " + s)
	}
	return *n
}

// IsPrivate reports whether every IP in the target CIDR or single address
// is contained within a private/link-local range.
// Returns false (not private) if the target string cannot be parsed.
func IsPrivate(target string) bool {
	if ip := net.ParseIP(target); ip != nil {
		return isPrivateIP(ip)
	}
	_, ipNet, err := net.ParseCIDR(target)
	if err != nil {
		return false
	}
	// Check first and last usable address; both must be private.
	first := firstIP(ipNet)
	last := lastIP(ipNet)
	return isPrivateIP(first) && isPrivateIP(last)
}

func isPrivateIP(ip net.IP) bool {
	for _, n := range private {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func firstIP(n *net.IPNet) net.IP {
	ip := n.IP.Mask(n.Mask)
	out := make(net.IP, len(ip))
	copy(out, ip)
	return out
}

func lastIP(n *net.IPNet) net.IP {
	ip := n.IP.Mask(n.Mask)
	mask := n.Mask
	out := make(net.IP, len(ip))
	for i := range ip {
		out[i] = ip[i] | ^mask[i]
	}
	return out
}

// DetectLocalSubnets returns the network CIDR for each active, non-loopback
// IPv4 interface whose address falls within a private (RFC1918) range.
// Results are returned as CIDR strings, e.g. "192.168.1.0/24".
// The slice is empty if no suitable interface is found.
func DetectLocalSubnets() []string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ipnet *net.IPNet
			switch v := addr.(type) {
			case *net.IPNet:
				ipnet = v
			case *net.IPAddr:
				ipnet = &net.IPNet{IP: v.IP, Mask: v.IP.DefaultMask()}
			}
			if ipnet == nil {
				continue
			}
			ip4 := ipnet.IP.To4()
			if ip4 == nil {
				continue // skip IPv6
			}
			if !isPrivateIP(ip4) {
				continue // skip public IPs
			}
			// Build the network address (host bits zeroed).
			network := &net.IPNet{
				IP:   ip4.Mask(ipnet.Mask),
				Mask: ipnet.Mask,
			}
			cidr := network.String()
			if !seen[cidr] {
				seen[cidr] = true
				out = append(out, cidr)
			}
		}
	}
	return out
}
