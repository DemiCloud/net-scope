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
