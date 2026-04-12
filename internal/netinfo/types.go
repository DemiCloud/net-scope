package netinfo

// ARPResult carries a single ARP table entry — either from the OS neighbor
// table (arp-snapshot) or from the continuous ARP poll (arp-start).
type ARPResult struct {
	IP      string `json:"ip"`
	MAC     string `json:"mac"`
	Type    string `json:"type,omitempty"`     // "dynamic", "static", "other"
	IfIndex uint32 `json:"if_index,omitempty"` // interface index
}

// DNSCacheEntry carries a single DNS resolver cache entry.
type DNSCacheEntry struct {
	Name string `json:"name"`
	Type string `json:"type"` // "A", "AAAA", "CNAME", "PTR", "MX", etc.
}

// RouteEntry carries a single IPv4 routing-table entry.
type RouteEntry struct {
	Dest     string `json:"dest"`
	Mask     string `json:"mask"`
	Gateway  string `json:"gateway"`
	IfIndex  uint32 `json:"if_index,omitempty"`
	Metric   uint32 `json:"metric,omitempty"`
	Protocol string `json:"protocol,omitempty"`
	Type     string `json:"type,omitempty"`
	Policy   uint32 `json:"policy,omitempty"`
}

// SocketEntry carries a single TCP or UDP socket entry.
type SocketEntry struct {
	Proto      string `json:"proto"`               // TCP, TCP6, UDP, UDP6
	LocalAddr  string `json:"local_addr"`
	LocalPort  uint16 `json:"local_port"`
	RemoteAddr string `json:"remote_addr,omitempty"`
	RemotePort uint16 `json:"remote_port,omitempty"`
	State      string `json:"state,omitempty"` // TCP only
	PID        uint32 `json:"pid,omitempty"`
	Process    string `json:"process,omitempty"`
}

// HostsEntry carries a single hosts-file entry.
type HostsEntry struct {
	IP        string   `json:"ip"`
	Hostnames []string `json:"hostnames"`
	Comment   string   `json:"comment,omitempty"`
}
