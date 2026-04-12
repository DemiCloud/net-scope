//go:build windows

package netinfo

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// IP_ADAPTER_DHCP_ENABLED is bit 2 of the Flags field in IpAdapterAddresses.
// https://learn.microsoft.com/en-us/windows/win32/api/iptypes/ns-iptypes-ip_adapter_addresses_lh
const ipAdapterDHCPEnabled = 0x0004

var winOperStateNames = map[uint32]string{
	windows.IfOperStatusUp:             "up",
	windows.IfOperStatusDown:           "down",
	windows.IfOperStatusTesting:        "testing",
	windows.IfOperStatusUnknown:        "unknown",
	windows.IfOperStatusDormant:        "dormant",
	windows.IfOperStatusNotPresent:     "not present",
	windows.IfOperStatusLowerLayerDown: "lower layer down",
}

// enrichInterfaceEntries populates Windows-specific fields for every entry
// in a single pair of API calls:
//
//   - GetAdaptersAddresses: description, DNS suffix, DNS servers,
//     DHCP status / server, link speed, operational status.
//   - GetIfEntry2Ex (per adapter): traffic counters.
func enrichInterfaceEntries(entries []InterfaceEntry) {
	// First call: determine required buffer size.
	var size uint32
	const flags = windows.GAA_FLAG_INCLUDE_GATEWAYS
	_ = windows.GetAdaptersAddresses(windows.AF_UNSPEC, flags, 0, nil, &size)
	if size == 0 {
		return
	}

	// Allocate with a margin; the list can grow between the two calls.
	buf := make([]byte, size+1024)
	aa := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0]))
	if err := windows.GetAdaptersAddresses(windows.AF_UNSPEC, flags, 0, aa, &size); err != nil {
		return
	}

	// Build index → adapter map.
	adapterByIdx := make(map[int]*windows.IpAdapterAddresses)
	for cur := aa; cur != nil; cur = cur.Next {
		adapterByIdx[int(cur.IfIndex)] = cur
		if int(cur.Ipv6IfIndex) != 0 && int(cur.Ipv6IfIndex) != int(cur.IfIndex) {
			adapterByIdx[int(cur.Ipv6IfIndex)] = cur
		}
	}

	for i := range entries {
		cur, ok := adapterByIdx[entries[i].Index]
		if !ok {
			continue
		}

		// Hardware / connection description (e.g. "Intel(R) Ethernet Connection").
		if cur.Description != nil {
			entries[i].Description = windows.UTF16PtrToString(cur.Description)
		}

		// DNS suffix (connection-specific, e.g. "corp.example.com").
		if cur.DnsSuffix != nil {
			entries[i].DNSSuffix = windows.UTF16PtrToString(cur.DnsSuffix)
		}

		// DNS servers (linked list).
		for dns := cur.FirstDnsServerAddress; dns != nil; dns = dns.Next {
			if ip := dns.Address.IP(); ip != nil {
				entries[i].DNSServers = append(entries[i].DNSServers, ip.String())
			}
		}

		// DHCP.
		entries[i].DHCPEnabled = cur.Flags&ipAdapterDHCPEnabled != 0
		if dhcpIP := cur.Dhcpv4Server.IP(); dhcpIP != nil && !dhcpIP.IsUnspecified() {
			entries[i].DHCPServer = dhcpIP.String()
		}

		// Link speed (TransmitLinkSpeed is in bps; ^uint64(0) means unknown/not applicable).
		if s := cur.TransmitLinkSpeed; s != 0 && s != ^uint64(0) {
			entries[i].Speed = int64(s / 1_000_000) // bps → Mbps
		} else if s := cur.ReceiveLinkSpeed; s != 0 && s != ^uint64(0) {
			entries[i].Speed = int64(s / 1_000_000)
		}

		// Operational status.
		if name, ok := winOperStateNames[cur.OperStatus]; ok {
			entries[i].OperState = name
		}

		// Traffic counters via GetIfEntry2Ex (uses LUID from IpAdapterAddresses).
		var row windows.MibIfRow2
		row.InterfaceLuid = cur.Luid
		if err := windows.GetIfEntry2Ex(windows.MibIfEntryNormal, &row); err == nil {
			entries[i].RXBytes   = row.InOctets
			entries[i].TXBytes   = row.OutOctets
			entries[i].RXPackets = row.InUcastPkts + row.InNUcastPkts
			entries[i].TXPackets = row.OutUcastPkts + row.OutNUcastPkts
			entries[i].RXErrors  = row.InErrors
			entries[i].TXErrors  = row.OutErrors
			entries[i].RXDropped = row.InDiscards
			entries[i].TXDropped = row.OutDiscards
		}
	}
}
