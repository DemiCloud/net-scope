# net-sweep — Backlog

## Naming / UX

- [ ] **Rename "Hosts" tab → "Scanner"** — clearer intent; "Hosts" is ambiguous with the Hosts menu
- [ ] **Tools menu** (replaces current Hosts menu) — contains "View All Hosts…" and "Query Host…" (rename from "View Host…"); keeps probe utility accessible even with no active scan
- [ ] **"Query Host" available without a scan** — the host detail / probe dialog should work against any manually typed IP; useful for querying game servers, public hosts, etc. on arbitrary subnets
- [ ] **Nicer text-only dialogs** (FAQ, Help, etc.) — modern look: styled EDIT or custom owner-draw with proper padding, link-style text, maybe a header banner

## Bugs

- [ ] **Scanner tab — Target field background** — the Target text box appears with a different background colour from the rest of the toolbar strip; likely an unhandled WM_CTLCOLOREDIT on the scan bar; should match the window background
- [ ] **Query Host — OK/Cancel buttons overlap** — buttons are incorrectly positioned in the current dialog layout; need layout fix

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

- [ ] **Sortable columns** — single-click column header sorts rows; indicator (▲/▼) in header
- [ ] **Column customisation** — drag to reorder, right-click header for "Edit Columns" dialog (show/hide, restore defaults)
- [ ] **Multi-row right-click menus** — when multiple rows selected, hide single-host actions; Copy/Export include all selected rows
- [ ] **Broadcast tab empty-state overlays** — mDNS, SSDP, WSD, DHCP tabs should show a greyed-out "Listening — no traffic detected yet" placeholder (same style as Scanner tab) while empty
- [ ] **View All Hosts — live filter** — text box above the list; filters rows by IP or hostname as you type; Ctrl+F focuses it
- [ ] **Broadcast host decay** — row background fades normal → light yellow (2–5 min) → light orange (5–15 min) → light red (15+ min) since last broadcast seen; add relative "Last Seen" column (`32s`, `4m`, `18m`); both reset on re-detection
- [ ] **Explorer file icon** — embed RT_ICON + RT_GROUP_ICON in the `.syso` resource so the `.exe` shows the radar icon in Windows Explorer (requires dynamic gen-rsrc rewrite)
- [ ] **Null-value dash alignment** — `—` placeholders in right-aligned columns (Latency, Ports) should render right-aligned; check whether LVCFMT is honoured or if custom draw is needed
- [ ] **Publisher / company info** — populate product description, company name, and icon in the About/version dialog so the app looks professional
- [ ] **"Databases" sub-menu** — replace the current single "Mac Vendors" menu item with a "Databases" sub-menu containing "Mac Vendors…" as the first entry; future diff/snapshot databases can be added here
- [ ] **Scan Report empty-state overlay** — the Scan Report tab has no placeholder; add one matching the style of the other tabs
- [ ] **Scan Report — scan duration metric** — record the wall-clock time from scan start to WM_SCAN_COMPLETE and display it in the Scan Report tab (e.g. "Scan completed in 4.2 s")
- [ ] **Win32 internal framework cleanup** — audit `cmd/gui-win/` for duplicated scaffolding (dialog creation, layout helpers, font caching, etc.) and extract into a small internal framework; goal is zero copy-paste between dialogs
- [ ] **README.md** — generate a project README covering build instructions, usage, screenshots, and contributing guidelines
- [ ] **GitHub Wiki / FAQ** — move the FAQ content to a GitHub Wiki page; update the Options → FAQ menu item to open the wiki URL in the default browser instead of showing the inline dialog; note: the GitHub Wiki lives in a separate companion repo (`<repo>.wiki.git`) — it is not part of the main repo's commit history, but can be cloned/edited independently
