package sweep

import (
	"fmt"
	"net"
)

// findInterface returns the network interface whose address is in the same
// subnet as ip. Used to select the right interface for ARP scanning.
func findInterface(ip net.IP) (*net.Interface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
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
			if ipnet != nil && ipnet.Contains(ip) {
				return &iface, nil
			}
		}
	}
	return nil, fmt.Errorf("no interface found for %s", ip)
}

// ExpandTarget is the exported form of expandTarget, for use by frontends
// that need to enumerate the full target range before starting a scan.
func ExpandTarget(target string) ([]net.IP, error) { return expandTarget(target) }

// expandTarget parses a CIDR block or single IP and returns all host IPs.
func expandTarget(target string) ([]net.IP, error) {
	// Single IP
	if ip := net.ParseIP(target); ip != nil {
		return []net.IP{ip.To4()}, nil
	}

	// CIDR range
	ip, ipnet, err := net.ParseCIDR(target)
	if err != nil {
		return nil, fmt.Errorf("invalid target %q: must be an IP or CIDR", target)
	}

	// Normalise to 4-byte IPv4 so String() always gives dotted-quad notation.
	start := ip.Mask(ipnet.Mask).To4()
	if start == nil {
		return nil, fmt.Errorf("only IPv4 targets are supported")
	}

	var hosts []net.IP
	for cur := start; ipnet.Contains(cur); incrementIP(cur) {
		host := make(net.IP, 4)
		copy(host, cur)
		hosts = append(hosts, host)
	}

	// Drop network and broadcast addresses for IPv4 /31 and smaller
	if len(hosts) > 2 {
		hosts = hosts[1 : len(hosts)-1]
	}

	return hosts, nil
}

func incrementIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			break
		}
	}
}
