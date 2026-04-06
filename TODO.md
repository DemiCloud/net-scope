# net-sweep — Backlog

## Naming / UX

- [ ] **Rename "Hosts" tab → "Scanner"** — clearer intent; "Hosts" is ambiguous with the Hosts menu
- [ ] **Tools menu** (replaces current Hosts menu) — contains "View All Hosts…" and "Query Host…" (rename from "View Host…"); keeps probe utility accessible even with no active scan
- [ ] **"Query Host" available without a scan** — the host detail / probe dialog should work against any manually typed IP; useful for querying game servers, public hosts, etc. on arbitrary subnets
- [ ] **Nicer text-only dialogs** (FAQ, Help, etc.) — modern look: styled EDIT or custom owner-draw with proper padding, link-style text, maybe a header banner

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
- [ ] **Win32 internal framework cleanup** — audit `cmd/gui-win/` for duplicated scaffolding (dialog creation, layout helpers, font caching, etc.) and extract into a small internal framework; goal is zero copy-paste between dialogs
- [ ] **README.md** — generate a project README covering build instructions, usage, screenshots, and contributing guidelines
- [ ] **GitHub Wiki / FAQ** — move the FAQ content to a GitHub Wiki page; update the Options → FAQ menu item to open the wiki URL in the default browser instead of showing the inline dialog; note: the GitHub Wiki lives in a separate companion repo (`<repo>.wiki.git`) — it is not part of the main repo's commit history, but can be cloned/edited independently
