package netinfo

import "sort"

// ARPConflict reports an IP that is answered by more than one distinct MAC
// address in the ARP table, which may indicate an IP address conflict between
// two devices, or active ARP spoofing/poisoning.
type ARPConflict struct {
	IP   string   // conflicting IPv4 address
	MACs []string // distinct MACs seen for this IP, sorted for determinism
}

// FindARPConflicts scans entries for IPs mapped to more than one distinct MAC.
// An IP that appears on multiple interfaces with the same MAC is not a conflict.
// Returns a deterministically sorted slice (by IP); nil if no conflicts exist.
func FindARPConflicts(entries []ARPResult) []ARPConflict {
	// ip → set of distinct MAC strings
	seen := make(map[string]map[string]struct{})
	for _, e := range entries {
		if e.IP == "" || e.MAC == "" {
			continue
		}
		if seen[e.IP] == nil {
			seen[e.IP] = make(map[string]struct{})
		}
		seen[e.IP][e.MAC] = struct{}{}
	}

	var conflicts []ARPConflict
	for ip, macs := range seen {
		if len(macs) > 1 {
			list := make([]string, 0, len(macs))
			for m := range macs {
				list = append(list, m)
			}
			sort.Strings(list)
			conflicts = append(conflicts, ARPConflict{IP: ip, MACs: list})
		}
	}
	sort.Slice(conflicts, func(i, j int) bool {
		return conflicts[i].IP < conflicts[j].IP
	})
	return conflicts
}
