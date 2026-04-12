package scan

import (
	"net"
	"strings"
)

// InterfaceEntry describes a single local network interface and its current
// addressing state.  All fields except Name and State may be zero/empty when
// the information is not available on a given platform.
type InterfaceEntry struct {
	Name     string   `json:"name"`
	Index    int      `json:"index"`
	MAC      string   `json:"mac,omitempty"`
	Addrs4   []string `json:"addrs4,omitempty"`   // IPv4 CIDR addresses, e.g. "192.168.1.2/24"
	Addrs6   []string `json:"addrs6,omitempty"`   // IPv6 CIDR addresses, e.g. "fe80::1/64"
	Gateway4 string   `json:"gateway4,omitempty"` // best-effort default IPv4 gateway
	MTU      int      `json:"mtu,omitempty"`
	State    string   `json:"state"` // "up" or "down"
	Type     string   `json:"type"`  // "ethernet", "wifi", "loopback", "tunnel", "virtual", "other"
}

// ReadInterfaces returns all local network interfaces with their addresses
// and a best-effort default gateway derived from the system route table.
// The route table is queried once; interfaces without a matching default route
// will have an empty Gateway4 field.
func ReadInterfaces() []InterfaceEntry {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}

	gw := interfaceGateways()

	out := make([]InterfaceEntry, 0, len(ifaces))
	for _, iface := range ifaces {
		var addrs4, addrs6 []string
		if addrs, err := iface.Addrs(); err == nil {
			for _, a := range addrs {
				var ip net.IP
				cidr := a.String()
				switch v := a.(type) {
				case *net.IPNet:
					ip = v.IP
				case *net.IPAddr:
					ip = v.IP
					if ip.To4() != nil {
						cidr = ip.String() + "/32"
					} else {
						cidr = ip.String() + "/128"
					}
				}
				if ip == nil {
					continue
				}
				if ip.To4() != nil {
					addrs4 = append(addrs4, cidr)
				} else {
					addrs6 = append(addrs6, cidr)
				}
			}
		}

		state := "down"
		if iface.Flags&net.FlagUp != 0 {
			state = "up"
		}

		mac := ""
		if len(iface.HardwareAddr) > 0 {
			mac = iface.HardwareAddr.String()
		}

		out = append(out, InterfaceEntry{
			Name:     iface.Name,
			Index:    iface.Index,
			MAC:      mac,
			Addrs4:   addrs4,
			Addrs6:   addrs6,
			Gateway4: gw[iface.Index],
			MTU:      iface.MTU,
			State:    state,
			Type:     ifaceKind(iface),
		})
	}
	return out
}

// ifaceKind returns a human-readable interface category based on flags and
// the interface name.  Detection is best-effort and covers common Linux and
// Windows naming conventions.
func ifaceKind(iface net.Interface) string {
	if iface.Flags&net.FlagLoopback != 0 {
		return "loopback"
	}
	lower := strings.ToLower(iface.Name)
	switch {
	case strings.HasPrefix(lower, "wlan") || strings.HasPrefix(lower, "wlp") ||
		strings.Contains(lower, "wi-fi") || strings.Contains(lower, "wifi") ||
		strings.HasPrefix(lower, "ath"):
		return "wifi"
	case strings.HasPrefix(lower, "tun") || strings.HasPrefix(lower, "tap") ||
		strings.Contains(lower, "tunnel") || strings.Contains(lower, "vpn") ||
		strings.HasPrefix(lower, "wg") || strings.HasPrefix(lower, "utun"):
		return "tunnel"
	case strings.HasPrefix(lower, "eth") || strings.HasPrefix(lower, "enp") ||
		strings.HasPrefix(lower, "ens") || strings.HasPrefix(lower, "eno") ||
		strings.HasPrefix(lower, "ethernet") || strings.HasPrefix(lower, "local area"):
		return "ethernet"
	case strings.HasPrefix(lower, "docker") || strings.HasPrefix(lower, "veth") ||
		strings.HasPrefix(lower, "virbr") || strings.HasPrefix(lower, "br-"):
		return "virtual"
	default:
		return "other"
	}
}

// interfaceGateways returns a map from interface index to the best-effort
// default IPv4 gateway for that interface, derived from the routing table.
// On platforms where ReadRouteTable does not populate IfIndex (e.g. Linux),
// gateways will not be mapped to specific interfaces and the map will be empty
// or keyed at index 0 only.
func interfaceGateways() map[int]string {
	gw := make(map[int]string)
	for _, r := range ReadRouteTable() {
		if r.Dest == "0.0.0.0" && r.Gateway != "" && r.Gateway != "0.0.0.0" {
			idx := int(r.IfIndex)
			if _, exists := gw[idx]; !exists {
				gw[idx] = r.Gateway
			}
		}
	}
	return gw
}
