# net-sweep — Backlog

## GUI (Windows)

- [ ] **Sortable columns** — single-click column header sorts rows; indicator (▲/▼) in header
- [ ] **Column customisation** — drag to reorder, right-click header for "Edit Columns" dialog (show/hide, restore defaults)
- [ ] **Multi-row right-click menus** — when multiple rows selected, hide single-host actions; Copy/Export include all selected rows
- [ ] **Explorer file icon** — embed RT_ICON + RT_GROUP_ICON in the `.syso` resource so the `.exe` shows the radar icon in Windows Explorer (requires dynamic gen-rsrc rewrite)
- [ ] **Null-value dash alignment** — `—` placeholders in right-aligned columns (Latency, Ports) should render right-aligned, not left; check whether LVCFMT is actually honoured for `—` cells or if custom draw is needed
- [ ] **Publisher / company info** — populate product description, company name, and icon in the About/version dialog so the app looks professional
