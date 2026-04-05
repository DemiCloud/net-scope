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
