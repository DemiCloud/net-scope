# NetScope — Backlog

## Naming / UX

- [ ] **Nicer text-only dialogs** (FAQ, Help, etc.) — modern look: styled EDIT or custom owner-draw with proper padding, link-style text, maybe a header banner

## Query Host (redesign)

- [ ] **Query Host full redesign** — replace the simple picker with a self-contained probe+scan dialog:
  - IP / hostname field (pre-populated from combo, editable)
  - **Port scan section**: mode selector (Default ports / Specific ports / All ports — all 65 535); port list edit field (enabled for Specific mode); results list
  - **Custom query section**: query-type selector (TCP, SSH, HTTP, HTTPS, FTP, SMTP, Telnet, RDP, …) with port field that auto-fills the well-known port for the selected type; Run button; result pane
  - Essentially merges the old picker with the host detail probe panel into one standalone dialog that requires no prior scan

## Scanner / Performance

- [ ] **All-ports scan mode** — add a "Scan all ports (1–65535)" option; since this is 65 535 TCP probes per host it requires a proper worker-pool implementation (see below)
- [ ] **Worker-pool port scanner** — replace the current goroutine-per-probe approach with a bounded worker pool; default concurrency = "auto" (calculated from available CPU cores and typical socket limits); expose as a Settings field so the user can cap it manually; target: no goroutine explosion even on /24 all-ports scan
- [ ] **Safe scanning mode** — a checkbox in Settings and on the Scanner toolbar; when enabled: lower concurrency cap, longer timeouts, randomise probe order, and suppress raw-socket operations; intended for environments where aggressive scanning would trip IDS/firewalls or violate policy; default off, but recommended UI hint when not running as admin

## Service Security

- [ ] **GUI ↔ service communication hardening** — the current JSON-over-TCP channel on 127.0.0.1 is loopback-only, but any local process could connect; evaluate options: (a) shared secret / nonce handshake, (b) named pipe instead of TCP (Windows-native, ACL-controllable), (c) TLS with a self-signed cert generated at service start; named pipe is likely the right answer for Windows — eliminates the TCP attack surface entirely and integrates naturally with Windows ACLs; document the decision and threat model in a comment in `service.go`

## GUI (Windows)

- [x] **Scanner tab — "Show Active Only" toggle** — add a checkbox (or toolbar toggle button) to the Scanner tab that hides all unresponsive (red/dead) rows; when enabled only live hosts are visible; toggling off restores the full list; helps usability on /24+ scans where dead IPs bury active devices; consider defaulting to enabled after a scan completes
- [ ] **Scanner tab — inline search/filter** — text input above the result list that filters visible rows by IP, MAC address, hostname, or vendor as the user types; Ctrl+F focuses it; complements (or supersedes) the planned "View All Hosts" live filter for the main scanner view; useful once host counts grow past ~20
- [ ] **Multi-row right-click menus** — when multiple rows selected, hide single-host actions; Copy/Export include all selected rows
- [ ] **View All Hosts — live filter** — text box above the list; filters rows by IP or hostname as you type; Ctrl+F focuses it
- [ ] **Broadcast host decay** — row background fades normal → light yellow (2–5 min) → light orange (5–15 min) → light red (15+ min) since last broadcast seen; add relative "Last Seen" column (`32s`, `4m`, `18m`); both reset on re-detection

## Export

- [ ] **File > Export should export all known hosts** — currently exports only the rows visible in the last active scan; it should export the full `hostRegistry` (every host seen across all scans and broadcast events in the session), including enrichment data (DHCP hostnames, NetBIOS names, ARP MACs accumulated post-scan); JSON and CSV both affected
- [ ] **File > Export Current Scan** — add a separate menu item that exports only the results from the most recently completed scan (i.e. `allScanResults` / the current ListView contents), for users who want a point-in-time snapshot rather than the full session history

## OS / Host Intelligence

- [x] **Extend `guessOS()` with vendor OUI signals** — vendor OUI tier added between SNMP and SSH checks: Apple → macOS; Raspberry Pi → Linux; Cisco/Juniper/Ubiquiti/MikroTik/Aruba/Fortinet/Palo Alto → Network Device
- [x] **TCP SYN window-size probe for OS fingerprinting**
- [x] **Raw fingerprint dump tool** — surface raw TCP/IP stack signals collected for a host (ICMP TTL, SYN-ACK window size, TCP options order, SNMP sysDescr, SSH banner, HTTP Server header, mDNS/SSDP service strings) in a copyable text format; useful for crafting new `guessOS()` rules; expose via right-click context menu, Tools menu, or a debug panel

## ARP Integrity

- [ ] **Duplicate IP detection** — after each scan, cross-reference the live ARP table; report any IP mapped to more than one MAC address (IP conflict or potential ARP spoofing); surface as a warning badge in the Scan Report tab
- [ ] **MAC flapping detection** — across successive scans within a session, track MAC→IP history; flag any MAC that appears at a different IP than previously seen; distinguish normal DHCP renewal (short gap) from suspicious rapid changes; show in the Scan Report or a dedicated anomaly list
- [ ] **Stale ARP entry detection** — flag ARP table entries whose IP was not confirmed alive by the current scan; helps surface ghost hosts and stale DHCP leases; surface in Scan Report
- [ ] **"Flush ARP for this IP" context action** — right-click a host row; on Windows runs `arp -d <ip>` (requires elevation); on Linux `ip neigh del <ip> dev <iface>`; prompt for elevation if not already elevated
- [ ] **"Ping scan → repopulate ARP"** — toolbar or context action that sends a fast ICMP echo to every address in the target subnet before scanning, forcing the OS ARP cache to populate; useful when cache is cold or stale; reuses the existing ICMP prober

## Extended Service Probes

- [ ] **SMB version negotiation probe** — on port 445: send an SMBv2 NEGOTIATE request; record the highest supported dialect (e.g. SMB 3.1.1); additionally send an SMBv1 negotiate to detect legacy enablement; add a "SMBv1!" warning badge in the Banner column; no authentication required
- [ ] **RDP handshake check** — on port 3389: complete the X.224 Connection Request / Confirm exchange; record NLA requirement (Security layer), offered certificate CN, and RDP version; surface in Banner column; no credentials needed
- [ ] **LDAP ping** — on port 389 (and 3268 for GC): send an anonymous LDAP RootDSE query; record `defaultNamingContext`, `supportedLDAPVersion`, server type; useful for automatic DC/AD detection; surface domain name in Banner column
- [ ] **MQTT broker detection** — on port 1883: send a minimal MQTT CONNECT packet (protocol level 4, no credentials); record whether anonymous connection is accepted or rejected (CONNACK return code); an open anonymous broker is a security finding; surface in Banner column
- [ ] **WireGuard presence probe** — on UDP port 51820: send a minimal handshake-initiation message; infer endpoint presence from a correctly structured response (type=2) or a deliberate rejection; note: WireGuard is intentionally silent so absence of response is not definitive; surface as "WireGuard?" in Banner when a valid response is received

## Wake-on-LAN

- [ ] **Wake-on-LAN tool** — `Tools > Wake on LAN…`: MAC address field (auto-populated from selected Scanner row if available) + optional broadcast IP (defaults to subnet broadcast derived from current target); sends the 102-byte magic packet (6× `0xFF` + 16× target MAC) as a UDP broadcast on port 9; no elevation required; show confirmation in the status bar on send

## MAC Vendor Lookup

- [ ] **MAC Vendor Lookup tool** — `Tools > MAC Vendor Lookup…`: MAC address input field (accepts full MAC or OUI prefix, colon/hyphen/dot-separated or plain hex); looks up the vendor string from the embedded OUI database; shows result inline in the dialog; useful for identifying unknown hardware without running a full scan

## Network Interfaces

- [ ] **Interfaces tab** — new tab listing all local NICs: adapter name, description, link speed, duplex (where exposed), driver version + date, MTU, IPv4 + IPv6 addresses, DHCP vs static, DHCPv6 state, offload capabilities (checksum offload, LSO, RSS); on Windows read via `GetAdaptersAddresses` + WMI `Win32_NetworkAdapter`; on Linux via `net.Interfaces()` + `/sys/class/net/<iface>/`
- [ ] **Interface flap/reset counter** — within a session, poll NIC operational state periodically; track up→down→up transitions per adapter; show flap count in the Interfaces tab; surface as a Scan Report warning if any flaps occurred during the last scan window

## Routing Diagnostics

- [ ] **Routing diagnostics panel** — new sub-panel in Scan Report (or a dedicated "Routing" tab): active default gateway(s) with interface binding; full IPv4/IPv6 route table; **duplicate gateway detection** (same metric, different interfaces — often a misconfiguration); **asymmetric route hint** (next-hop for return path differs from outbound — inferred by comparing gateway MACs against scanner results); on Windows use `GetIpForwardTable2`; on Linux parse `ip route`

## Traceroute

- [ ] **Traceroute tool** — `Tools > Traceroute…` (or a panel in the planned Query Host redesign): target IP/hostname input; sends ICMP (Windows) or UDP (Linux) probes with TTL 1…30; for each hop: hop number, IP, rDNS name, RTT (3 probes, show min/avg/max), **Δ from previous hop**; highlight anomalies: RTT inversion (hop N+1 is faster than N by > 20 ms), non-responding hops (`*`), private→public→private path re-entry; requires raw socket → elevation prompt if not elevated

## Local Hardening Audit

- [ ] **Local hardening check** — new "Security" tab or collapsible Scan Report section showing the local host's security posture; each item shows Pass / Warn / Fail + a one-line remediation hint:
  - SMBv1 enabled (`HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\SMB1`)
  - LLMNR enabled (`HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\EnableMulticast`)
  - NetBIOS over TCP/IP enabled (per-adapter via `GetAdaptersInfo` or registry)
  - Unauthenticated guest share access (`HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters\AllowInsecureGuestAuth`)
  - RDP NLA not required (`HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\UserAuthentication` should be 1)
- [ ] **Firewall profile surface** — show active Windows Firewall profile(s) (Domain / Private / Public) and their inbound/outbound default action; list services currently listening on each interface (from `GetExtendedTcpTable` / `GetExtendedUdpTable`); optional **port block test** — attempt a loopback connection to a user-specified port and report whether the local firewall intercepts it

## Linux GUI

- [ ] **Linux native GUI** — Gio is the chosen toolkit: no CGo on Windows (cross-compile from WSL unchanged), CGo+EGL on Linux (native build with gcc + wayland-devel/libX11-devel/mesa-libEGL-devel); immediate-mode model suits live scan data well; Linux GUI should reuse the same sensor service IPC channel as the Windows GUI; FreeBSD stays CLI/TUI only

## Diff / Snapshot

- [ ] **Diff / snapshot system** — capture a point-in-time snapshot of the host registry; compare against a later scan or a saved snapshot; surface added/removed/changed hosts; useful for change detection on monitored networks

## Filter Language

- [ ] **Filter language** — typed filter input accepting predicates like `alive`, `open:22`, `vendor:Cisco`; applies to the active tab's list; complements the per-tab search bar

## Debug / Diagnostics Menu

- [ ] **Debug menu (ARP/DNS inspect/clear)** — developer/power-user menu item (hidden behind a flag or key combo) to inspect the live ARP cache, DNS cache, and force-clear them without leaving the app

## Broadcast Tab

- [x] **Broadcast tab auto-poll** — periodic background refresh of the broadcast/mDNS/SSDP/WSD tabs on a configurable interval rather than only on manual trigger

## Admin Mode

- [x] **Admin mode toggle** — in-app button or menu item to relaunch self elevated (UAC prompt) without closing and re-opening manually; Windows only; Linux stub

## Event Log

- [ ] **Network event log viewer** — `Diagnostics > Network Events…` or a dedicated tab; on-demand query of Windows Event Log for network-relevant entries:
  - DHCP client lease failures (System log, source `Microsoft-Windows-Dhcp-Client`, Event IDs 1001/1002/1003)
  - DNS client failures (`Microsoft-Windows-DNS-Client`)
  - NIC reset / removal (System, NDIS source, Event IDs 10317/10319 or adapter-specific)
  - Windows Firewall drop events (Security log, Event ID 5152 — requires audit policy enabled)
  - TLS/SChannel handshake failures (System, source `Schannel`, Event IDs 36871/36874)
  - Display as a listview: Timestamp | Source | Event ID | Summary; allow filtering by time range and source; Windows-only (stub out gracefully on Linux)
