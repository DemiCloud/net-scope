# NetScope — Backlog

## Naming / UX

- [x] **Rename "Hosts" tab → "Scanner"** — clearer intent; "Hosts" is ambiguous with the Hosts menu
- [x] **Tools menu** (replaces current Hosts menu) — contains "View All Hosts…" and "Query Host…" (rename from "View Host…"); keeps probe utility accessible even with no active scan
- [x] **"Query Host" available without a scan** — the host detail / probe dialog should work against any manually typed IP; useful for querying game servers, public hosts, etc. on arbitrary subnets
- [ ] **Nicer text-only dialogs** (FAQ, Help, etc.) — modern look: styled EDIT or custom owner-draw with proper padding, link-style text, maybe a header banner

## Bugs

- [x] **Scanner tab — Target field background** — fixed: switched to `WS_EX_CLIENTEDGE` and return `COLOR_WINDOW` for all unhandled `WM_CTLCOLORSTATIC` on the main window
- [x] **Query Host — OK/Cancel buttons overlap** — fixed: taller dialog (145px) + new `dlgBottomRight` framework helper used for layout

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

- [ ] **Elevation state → status bar** — remove the green "ARP + ICMP active" banner that currently appears at the top of the window when elevation is acquired; instead, reflect the elevated scan mode (ARP + ICMP active) directly in the status bar with a green-accented indicator; this eliminates a redundant UI element and fixes the conflicting state where "Service Running – TCP only: Scanning" overwrites scan-progress text in the same bar
- [ ] **Scanner tab — "Show Active Only" toggle** — add a checkbox (or toolbar toggle button) to the Scanner tab that hides all unresponsive (red/dead) rows; when enabled only live hosts are visible; toggling off restores the full list; helps usability on /24+ scans where dead IPs bury active devices; consider defaulting to enabled after a scan completes
- [ ] **Scanner tab — inline search/filter** — text input above the result list that filters visible rows by IP, MAC address, hostname, or vendor as the user types; Ctrl+F focuses it; complements (or supersedes) the planned "View All Hosts" live filter for the main scanner view; useful once host counts grow past ~20
- [ ] **Sortable columns** — single-click column header sorts rows; indicator (▲/▼) in header
- [ ] **Column customisation** — drag to reorder, right-click header for "Edit Columns" dialog (show/hide, restore defaults)
- [ ] **Multi-row right-click menus** — when multiple rows selected, hide single-host actions; Copy/Export include all selected rows
- [x] **Broadcast tab empty-state overlays** — mDNS, SSDP, WSD, DHCP tabs all have greyed-out placeholders matching the Scanner tab style
- [ ] **View All Hosts — live filter** — text box above the list; filters rows by IP or hostname as you type; Ctrl+F focuses it
- [ ] **Broadcast host decay** — row background fades normal → light yellow (2–5 min) → light orange (5–15 min) → light red (15+ min) since last broadcast seen; add relative "Last Seen" column (`32s`, `4m`, `18m`); both reset on re-detection
- [ ] **Explorer file icon** — embed RT_ICON + RT_GROUP_ICON in the `.syso` resource so the `.exe` shows the radar icon in Windows Explorer (requires dynamic gen-rsrc rewrite)
- [x] **Null-value dash alignment** — verified: Latency and Ports columns use `LVCF_FMT | LVCFMT_RIGHT`; hide/show only changes width so format is preserved; custom draw returns `CDRF_NEWFONT` (not `CDRF_SKIPDEFAULT`) so Win32 still applies alignment; no fix needed
- [x] **Publisher / company info** — About dialog now shows version, description, copyright, and GitHub URL
- [x] **"Databases" sub-menu** — `Options > Databases > Mac Vendors…`; future database types slot in as siblings
- [x] **Scan Report empty-state overlay** — `hwndHealthPlaceholder` STATIC shown until first scan completes, then hidden permanently
- [ ] **Scan Report — scan duration metric** — record the wall-clock time from scan start to WM_SCAN_COMPLETE and display it in the Scan Report tab (e.g. "Scan completed in 4.2 s")
- [x] **Win32 internal framework cleanup** — `fw_win32.go` + `fw_dialog.go` extracted; `dlgBottomRight`, `registerDialogClass`, `ctlColorDialog` added; `win32.go` is now app-constants-only
- [x] **Scan Report — scan duration metric** — wall-clock time shown in status bar and Scan Report tab
- [x] **GitHub Wiki / FAQ** — FAQ content moved to `.wiki/FAQ.md`; `Options → Help / FAQ…` now opens `https://github.com/demicloud/net-scope/wiki/FAQ` in the default browser via `ShellExecute`; inline dialog and `faqText` constant removed

## OS / Host Intelligence

- [ ] **Extend `guessOS()` with port-pattern and vendor signals** — add two new signal tiers inserted between the SNMP and SSH checks: (1) **vendor OUI**: "Apple" prefix → macOS; "Raspberry Pi Foundation" → Linux; known network-gear vendors (Cisco, Juniper, Ubiquiti, MikroTik, etc.) → Network Device; (2) **open-port fingerprint**: ports 445 or 139 present → Windows; port 22 present with no 445/139 → Linux (raise confidence, don't override higher-tier signals); port 23 (Telnet) or 161 (SNMP) with no other signals → Network Device; pass the `[]int` open-port slice and `string` vendor into `guessOS()` and update all call sites

## ARP Integrity

- [ ] **Duplicate IP detection** — after each scan, cross-reference the live ARP table; report any IP mapped to more than one MAC address (IP conflict or potential ARP spoofing); surface as a warning badge in the Scan Report tab
- [ ] **MAC flapping detection** — across successive scans within a session, track MAC→IP history; flag any MAC that appears at a different IP than previously seen; distinguish normal DHCP renewal (short gap) from suspicious rapid changes; show in the Scan Report or a dedicated anomaly list
- [ ] **Stale ARP entry detection** — flag ARP table entries whose IP was not confirmed alive by the current scan; helps surface ghost hosts and stale DHCP leases; surface in Scan Report
- [ ] **"Flush ARP for this IP" context action** — right-click a host row; on Windows runs `arp -d <ip>` (requires elevation); on Linux `ip neigh del <ip> dev <iface>`; prompt for elevation if not already elevated
- [ ] **"Ping sweep → repopulate ARP"** — toolbar or context action that sends a fast ICMP echo to every address in the target subnet before scanning, forcing the OS ARP cache to populate; useful when cache is cold or stale; reuses the existing ICMP prober

## Extended Service Probes

- [ ] **SMB version negotiation probe** — on port 445: send an SMBv2 NEGOTIATE request; record the highest supported dialect (e.g. SMB 3.1.1); additionally send an SMBv1 negotiate to detect legacy enablement; add a "SMBv1!" warning badge in the Banner column; no authentication required
- [ ] **RDP handshake check** — on port 3389: complete the X.224 Connection Request / Confirm exchange; record NLA requirement (Security layer), offered certificate CN, and RDP version; surface in Banner column; no credentials needed
- [ ] **LDAP ping** — on port 389 (and 3268 for GC): send an anonymous LDAP RootDSE query; record `defaultNamingContext`, `supportedLDAPVersion`, server type; useful for automatic DC/AD detection; surface domain name in Banner column
- [ ] **MQTT broker detection** — on port 1883: send a minimal MQTT CONNECT packet (protocol level 4, no credentials); record whether anonymous connection is accepted or rejected (CONNACK return code); an open anonymous broker is a security finding; surface in Banner column
- [ ] **WireGuard presence probe** — on UDP port 51820: send a minimal handshake-initiation message; infer endpoint presence from a correctly structured response (type=2) or a deliberate rejection; note: WireGuard is intentionally silent so absence of response is not definitive; surface as "WireGuard?" in Banner when a valid response is received

## Wake-on-LAN

- [ ] **Wake-on-LAN tool** — `Tools > Wake on LAN…`: MAC address field (auto-populated from selected Scanner row if available) + optional broadcast IP (defaults to subnet broadcast derived from current target); sends the 102-byte magic packet (6× `0xFF` + 16× target MAC) as a UDP broadcast on port 9; no elevation required; show confirmation in the status bar on send

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

## Event Log

- [ ] **Network event log viewer** — `Diagnostics > Network Events…` or a dedicated tab; on-demand query of Windows Event Log for network-relevant entries:
  - DHCP client lease failures (System log, source `Microsoft-Windows-Dhcp-Client`, Event IDs 1001/1002/1003)
  - DNS client failures (`Microsoft-Windows-DNS-Client`)
  - NIC reset / removal (System, NDIS source, Event IDs 10317/10319 or adapter-specific)
  - Windows Firewall drop events (Security log, Event ID 5152 — requires audit policy enabled)
  - TLS/SChannel handshake failures (System, source `Schannel`, Event IDs 36871/36874)
  - Display as a listview: Timestamp | Source | Event ID | Summary; allow filtering by time range and source; Windows-only (stub out gracefully on Linux)
