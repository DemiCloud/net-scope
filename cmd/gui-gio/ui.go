package guigio

import (
	"fmt"
	"image"
	"image/color"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"gioui.org/app"
	"gioui.org/font/gofont"
	"gioui.org/layout"
	"gioui.org/op"
	"gioui.org/op/clip"
	"gioui.org/op/paint"
	"gioui.org/text"
	"gioui.org/unit"
	"gioui.org/widget"
	"gioui.org/widget/material"

	"github.com/demicloud/net-scope/internal/config"
	"github.com/demicloud/net-scope/internal/scan"
)

// ---------------------------------------------------------------------------
// Colour palette — closely mirrors the Win32 GUI aesthetics
// ---------------------------------------------------------------------------

var (
	colBackground  = color.NRGBA{R: 0xF0, G: 0xF0, B: 0xF0, A: 0xFF}
	colHeader      = color.NRGBA{R: 0x2D, G: 0x2D, B: 0x2D, A: 0xFF}
	colHeaderText  = color.NRGBA{R: 0xFF, G: 0xFF, B: 0xFF, A: 0xFF}
	colRowEven     = color.NRGBA{R: 0xFF, G: 0xFF, B: 0xFF, A: 0xFF}
	colRowOdd      = color.NRGBA{R: 0xF5, G: 0xF5, B: 0xF5, A: 0xFF}
	colAlive       = color.NRGBA{R: 0x00, G: 0xAA, B: 0x00, A: 0xFF}
	colDead        = color.NRGBA{R: 0xCC, G: 0x00, B: 0x00, A: 0xFF}
	colPending     = color.NRGBA{R: 0x88, G: 0x88, B: 0x88, A: 0xFF}
	colStatusBar   = color.NRGBA{R: 0x2D, G: 0x2D, B: 0x2D, A: 0xFF}
	colStatusText  = color.NRGBA{R: 0xDD, G: 0xDD, B: 0xDD, A: 0xFF}
	colTabActive   = color.NRGBA{R: 0x00, G: 0x78, B: 0xD4, A: 0xFF}
	colTabInactive = color.NRGBA{R: 0xD0, G: 0xD0, B: 0xD0, A: 0xFF}
	colTabText     = color.NRGBA{R: 0x1A, G: 0x1A, B: 0x1A, A: 0xFF}
	colDivider     = color.NRGBA{R: 0xCC, G: 0xCC, B: 0xCC, A: 0xFF}
	colElevated    = color.NRGBA{R: 0x00, G: 0x78, B: 0x00, A: 0xFF}
	colWarning     = color.NRGBA{R: 0xCC, G: 0x66, B: 0x00, A: 0xFF}
)

// ---------------------------------------------------------------------------
// Tab identifiers
// ---------------------------------------------------------------------------

type tabID int

const (
	tabHosts tabID = iota
	tabMDNS
	tabSSDP
	tabWSD
	tabDHCP
	tabNetwork
	numTabs
)

var tabLabels = [numTabs]string{
	"Hosts", "mDNS", "SSDP", "WSD", "DHCP", "Network",
}

// ---------------------------------------------------------------------------
// Host row — display state for one entry in the Hosts tab
// ---------------------------------------------------------------------------

type hostRow struct {
	ip      string
	alive   bool
	pending bool // probe in progress
	result  scan.Result
}

// ---------------------------------------------------------------------------
// Broadcast / DHCP rows
// ---------------------------------------------------------------------------

type bcastRow struct {
	ip     string
	source string // "mdns", "ssdp", "wsd"
	name   string
	svcType string
	details string
}

type dhcpRow struct {
	evt scan.DHCPEvent
}

// ---------------------------------------------------------------------------
// UI state
// ---------------------------------------------------------------------------

type uiState struct {
	version string
	cfg     config.Config

	// service
	svc        *ServiceClient
	svcEvents  chan ServiceEvent
	svcStatus  string // shown in status bar right part
	uiInvalidate func() // triggers a Gio frame redraw

	// scan
	mu           sync.Mutex
	target       widget.Editor
	scanBtn      widget.Clickable
	detectBtn    widget.Clickable
	elevateBtn   widget.Clickable
	activeFilter widget.Bool

	isScanning  bool
	scanStatus  string
	liveCount   int
	hosts       []hostRow          // ordered by first-seen IP
	ipIndex     map[string]int     // IP → hosts slice index

	// broadcast tabs
	mdnsRows []bcastRow
	ssdpRows []bcastRow
	wsdRows  []bcastRow
	dhcpRows []dhcpRow

	// tabs
	activeTab tabID
	tabBtns   [numTabs]widget.Clickable

	// host list scroll
	hostList layout.List

	// theme
	th *material.Theme
}

// ---------------------------------------------------------------------------
// runUI — main Gio event loop
// ---------------------------------------------------------------------------

func runUI(version, initialTarget string, cfg config.Config) {
	fonts := gofont.Collection()
	th := material.NewTheme()
	th.Shaper = text.NewShaper(text.WithCollection(fonts))

	st := &uiState{
		version:  version,
		cfg:      cfg,
		svc:      NewServiceClient(),
		svcEvents: make(chan ServiceEvent, 256),
		svcStatus: "Service: starting…",
		ipIndex:  make(map[string]int),
		th:       th,
	}
	st.hostList.Axis = layout.Vertical
	st.target.SetText(initialTarget)
	st.target.SingleLine = true
	st.target.Submit = true

	w := new(app.Window)
	w.Option(
		app.Title("NetScope "+version),
		app.MinSize(unit.Dp(900), unit.Dp(550)),
		app.Size(unit.Dp(1160), unit.Dp(700)),
	)

	// Trigger a frame redraw from any goroutine.
	st.uiInvalidate = func() { w.Invalidate() }

	// Start the service (user-level).
	go func() {
		if err := st.svc.Start(false, st.svcEvents); err != nil {
			st.mu.Lock()
			st.svcStatus = "Service: " + err.Error()
			st.mu.Unlock()
			st.uiInvalidate()
			return
		}
	}()

	// Pump service events → UI state on a background goroutine.
	go st.handleServiceEvents()

	var ops op.Ops
	for {
		e := w.Event()
		switch e := e.(type) {
		case app.DestroyEvent:
			st.svc.Stop()
			os.Exit(0)
		case app.FrameEvent:
			gtx := app.NewContext(&ops, e)
			st.handleInput(gtx)
			st.draw(gtx)
			e.Frame(gtx.Ops)
		}
	}
}

// ---------------------------------------------------------------------------
// Service event handler (runs on a background goroutine)
// ---------------------------------------------------------------------------

func (st *uiState) handleServiceEvents() {
	for evt := range st.svcEvents {
		st.mu.Lock()
		switch {
		case evt.Ready:
			if evt.Elevated {
				st.svcStatus = "Service: running (Admin)"
			} else {
				st.svcStatus = "Service: running (User)"
			}
		case evt.Err != "":
			if strings.Contains(evt.Err, "service disconnected") {
				st.svcStatus = "Service: disconnected"
			} else {
				st.svcStatus = "Service: error"
			}
		case evt.Result != nil:
			r := *evt.Result
			ip := r.IP.String()
			if idx, ok := st.ipIndex[ip]; ok {
				st.hosts[idx] = hostRow{ip: ip, alive: r.Alive, result: r}
			} else {
				st.hosts = append(st.hosts, hostRow{ip: ip, alive: r.Alive, result: r})
				st.ipIndex[ip] = len(st.hosts) - 1
			}
			if r.Alive {
				st.liveCount++
			}
			st.updateScanStatus()
		case evt.Done:
			st.isScanning = false
			if evt.Stats != nil {
				st.scanStatus = fmt.Sprintf("Done — %d alive, %.0f ms avg",
					st.liveCount, evt.Stats.AvgLatencyMS())
			} else {
				st.scanStatus = fmt.Sprintf("Done — %d alive", st.liveCount)
			}
		case evt.DHCP != nil:
			st.dhcpRows = append(st.dhcpRows, dhcpRow{evt: *evt.DHCP})
		}
		st.mu.Unlock()
		st.uiInvalidate()
	}
}

func (st *uiState) updateScanStatus() {
	target := strings.TrimSpace(st.target.Text())
	st.scanStatus = fmt.Sprintf("Scanning %s… %d found", target, st.liveCount)
}

// ---------------------------------------------------------------------------
// Input handling
// ---------------------------------------------------------------------------

func (st *uiState) handleInput(gtx layout.Context) {
	// Tab switching.
	for i := range st.tabBtns {
		if st.tabBtns[i].Clicked(gtx) {
			st.activeTab = tabID(i)
		}
	}

	// Scan / Stop button.
	if st.scanBtn.Clicked(gtx) {
		st.mu.Lock()
		scanning := st.isScanning
		st.mu.Unlock()
		if scanning {
			st.svc.StopScan()
		} else {
			st.startScan()
		}
	}

	// Detect subnet button.
	if st.detectBtn.Clicked(gtx) {
		if subnets := scan.DetectLocalSubnets(); len(subnets) > 0 {
			st.target.SetText(subnets[0])
		}
	}

	// Elevate service button.
	if st.elevateBtn.Clicked(gtx) {
		go func() {
			st.svc.Stop()
			st.mu.Lock()
			st.svcStatus = "Service: elevating…"
			st.mu.Unlock()
			st.uiInvalidate()
			if err := st.svc.Start(true, st.svcEvents); err != nil {
				st.mu.Lock()
				st.svcStatus = "Service: elevation failed"
				st.mu.Unlock()
				st.uiInvalidate()
			}
		}()
	}

	// Enter key in target field triggers scan.
	for {
		ev, ok := st.target.Update(gtx)
		if !ok {
			break
		}
		if _, ok := ev.(widget.SubmitEvent); ok {
			st.startScan()
		}
	}
}

func (st *uiState) startScan() {
	target := strings.TrimSpace(st.target.Text())
	if target == "" || !st.svc.IsRunning() {
		return
	}
	scanCfg := st.cfg.ToScanConfig()

	st.mu.Lock()
	// Reset scan state.
	st.hosts = st.hosts[:0]
	st.ipIndex = make(map[string]int)
	st.liveCount = 0
	st.isScanning = true
	st.scanStatus = "Scanning " + target + "…"
	st.mu.Unlock()
	st.uiInvalidate()

	if err := st.svc.Scan(target, scanCfg); err != nil {
		st.mu.Lock()
		st.isScanning = false
		st.scanStatus = "Error: " + err.Error()
		st.mu.Unlock()
		st.uiInvalidate()
	}
}

// ---------------------------------------------------------------------------
// Drawing
// ---------------------------------------------------------------------------

func (st *uiState) draw(gtx layout.Context) layout.Dimensions {
	st.mu.Lock()
	defer st.mu.Unlock()

	fillRect(gtx, gtx.Constraints.Max, colBackground)

	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		// Top bar: Elevate + service status
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return st.drawTopBar(gtx)
		}),
		// Scan bar (always visible; irrelevant controls disabled on non-Hosts tabs)
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return st.drawScanBar(gtx)
		}),
		// Tab strip
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return st.drawTabs(gtx)
		}),
		// Content pane
		layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
			return st.drawContent(gtx)
		}),
		// Status bar
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return st.drawStatusBar(gtx)
		}),
	)
}

// drawTopBar renders the global options strip (elevation button, service status).
func (st *uiState) drawTopBar(gtx layout.Context) layout.Dimensions {
	th := st.th
	const h = 36
	gtx.Constraints.Min.Y = gtx.Dp(unit.Dp(h))
	gtx.Constraints.Max.Y = gtx.Dp(unit.Dp(h))
	fillRect(gtx, gtx.Constraints.Max, colHeader)

	return layout.Inset{Left: unit.Dp(8), Right: unit.Dp(8)}.Layout(gtx,
		func(gtx layout.Context) layout.Dimensions {
			return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					btn := material.Button(th, &st.elevateBtn, "▲ Elevate Sensor")
					btn.TextSize = unit.Sp(11)
					btn.Inset = layout.Inset{
						Top: unit.Dp(4), Bottom: unit.Dp(4),
						Left: unit.Dp(10), Right: unit.Dp(10),
					}
					if st.svc.IsElevated() {
						btn.Background = colElevated
					}
					return btn.Layout(gtx)
				}),
				layout.Rigid(spacer(16)),
				layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
					lbl := material.Body2(th, st.svcStatus)
					lbl.Color = colStatusText
					lbl.TextSize = unit.Sp(11)
					return lbl.Layout(gtx)
				}),
			)
		},
	)
}

// drawScanBar renders the target input + Scan button + status label.
func (st *uiState) drawScanBar(gtx layout.Context) layout.Dimensions {
	th := st.th
	const h = 40
	gtx.Constraints.Min.Y = gtx.Dp(unit.Dp(h))
	gtx.Constraints.Max.Y = gtx.Dp(unit.Dp(h))
	fillRect(gtx, gtx.Constraints.Max, colBackground)
	drawDivider(gtx, false)

	return layout.Inset{Left: unit.Dp(8), Right: unit.Dp(8), Top: unit.Dp(6), Bottom: unit.Dp(6)}.Layout(gtx,
		func(gtx layout.Context) layout.Dimensions {
			return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					lbl := material.Body2(th, "Target:")
					lbl.TextSize = unit.Sp(12)
					return lbl.Layout(gtx)
				}),
				layout.Rigid(spacer(8)),
				layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
					ed := material.Editor(th, &st.target, "e.g. 192.168.1.0/24")
					ed.TextSize = unit.Sp(12)
					gtx.Constraints.Max.X = gtx.Dp(unit.Dp(280))
					return ed.Layout(gtx)
				}),
				layout.Rigid(spacer(4)),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					btn := material.Button(th, &st.detectBtn, "⟲")
					btn.TextSize = unit.Sp(12)
					btn.Inset = layout.Inset{
						Top: unit.Dp(3), Bottom: unit.Dp(3),
						Left: unit.Dp(8), Right: unit.Dp(8),
					}
					return btn.Layout(gtx)
				}),
				layout.Rigid(spacer(8)),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					label := "Scan"
					if st.isScanning {
						label = "Stop"
					}
					btn := material.Button(th, &st.scanBtn, label)
					btn.TextSize = unit.Sp(12)
					btn.Inset = layout.Inset{
						Top: unit.Dp(3), Bottom: unit.Dp(3),
						Left: unit.Dp(16), Right: unit.Dp(16),
					}
					return btn.Layout(gtx)
				}),
				layout.Rigid(spacer(12)),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					lbl := material.Body2(th, st.scanStatus)
					lbl.TextSize = unit.Sp(11)
					lbl.Color = colPending
					if st.isScanning {
						lbl.Color = colTabActive
					}
					return lbl.Layout(gtx)
				}),
				layout.Rigid(spacer(12)),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return material.CheckBox(th, &st.activeFilter, "Active only").Layout(gtx)
				}),
			)
		},
	)
}

// drawTabs renders the tab strip.
func (st *uiState) drawTabs(gtx layout.Context) layout.Dimensions {
	th := st.th
	const h = 28
	gtx.Constraints.Min.Y = gtx.Dp(unit.Dp(h))
	gtx.Constraints.Max.Y = gtx.Dp(unit.Dp(h))
	fillRect(gtx, gtx.Constraints.Max, colBackground)
	drawDivider(gtx, false)

	children := make([]layout.FlexChild, numTabs)
	for i := range tabLabels {
		i := i
		active := tabID(i) == st.activeTab
		children[i] = layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			bg := colTabInactive
			textCol := colTabText
			if active {
				bg = colTabActive
				textCol = colHeaderText
			}
			return layout.Stack{}.Layout(gtx,
				layout.Stacked(func(gtx layout.Context) layout.Dimensions {
					return material.Clickable(gtx, &st.tabBtns[i], func(gtx layout.Context) layout.Dimensions {
						return layout.Inset{
							Left: unit.Dp(16), Right: unit.Dp(16),
							Top: unit.Dp(6), Bottom: unit.Dp(6),
						}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
							lbl := material.Body2(th, tabLabels[i])
							lbl.TextSize = unit.Sp(11)
							lbl.Color = textCol
							_ = bg
							return lbl.Layout(gtx)
						})
					})
				}),
			)
		})
	}

	return layout.Flex{Axis: layout.Horizontal}.Layout(gtx, children...)
}

// drawContent renders the active tab's content pane.
func (st *uiState) drawContent(gtx layout.Context) layout.Dimensions {
	switch st.activeTab {
	case tabHosts:
		return st.drawHostsTab(gtx)
	case tabMDNS:
		return st.drawBcastTab(gtx, "mDNS", []string{"Source", "IP", "Name", "Type", "Details"}, st.mdnsRowData())
	case tabSSDP:
		return st.drawBcastTab(gtx, "SSDP", []string{"Source", "IP", "Name", "Type", "Details"}, st.ssdpRowData())
	case tabWSD:
		return st.drawBcastTab(gtx, "WSD", []string{"Source", "IP", "Name", "Type", "Details"}, st.wsdRowData())
	case tabDHCP:
		return st.drawDHCPTab(gtx)
	case tabNetwork:
		return st.drawNetworkTab(gtx)
	default:
		return layout.Dimensions{}
	}
}

// drawHostsTab renders the host list with columns matching the Win32 GUI.
func (st *uiState) drawHostsTab(gtx layout.Context) layout.Dimensions {
	// Column headers
	headers := []string{"", "IP Address", "Hostname", "MAC", "Vendor", "OS", "Latency", "Ports", "Banner"}
	colWidths := []unit.Dp{28, 120, 160, 140, 140, 100, 70, 90, 0} // 0 = flex remainder

	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return st.drawTableHeader(gtx, headers, colWidths)
		}),
		layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
			hosts := st.visibleHosts()
			if len(hosts) == 0 {
				return st.drawPlaceholder(gtx, "No hosts yet — enter a target and click Scan")
			}
			return st.hostList.Layout(gtx, len(hosts), func(gtx layout.Context, i int) layout.Dimensions {
				return st.drawHostRow(gtx, i, hosts[i], colWidths)
			})
		}),
	)
}

func (st *uiState) visibleHosts() []hostRow {
	if !st.activeFilter.Value {
		return st.hosts
	}
	out := make([]hostRow, 0, len(st.hosts))
	for _, h := range st.hosts {
		if h.alive {
			out = append(out, h)
		}
	}
	return out
}

func (st *uiState) drawHostRow(gtx layout.Context, idx int, h hostRow, widths []unit.Dp) layout.Dimensions {
	th := st.th
	bg := colRowEven
	if idx%2 == 1 {
		bg = colRowOdd
	}

	const rowH = 22
	gtx.Constraints.Min.Y = gtx.Dp(unit.Dp(rowH))

	return layout.Stack{}.Layout(gtx,
		layout.Stacked(func(gtx layout.Context) layout.Dimensions {
			fillRect(gtx, gtx.Constraints.Max, bg)
			return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
				// Status dot
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					gtx.Constraints.Min.X = gtx.Dp(widths[0])
					gtx.Constraints.Max.X = gtx.Dp(widths[0])
					sym := "●"
					col := colAlive
					if h.pending {
						sym = "…"
						col = colPending
					} else if !h.alive {
						sym = "✕"
						col = colDead
					}
					lbl := material.Body2(th, sym)
					lbl.Color = col
					lbl.TextSize = unit.Sp(11)
					lbl.Alignment = text.Middle
					return layout.Inset{Left: unit.Dp(4)}.Layout(gtx, lbl.Layout)
				}),
				// IP
				layout.Rigid(cellLabel(th, h.ip, widths[1])),
				// Hostname
				layout.Rigid(cellLabel(th, hostname(h.result), widths[2])),
				// MAC
				layout.Rigid(cellLabel(th, macStr(h.result.MAC), widths[3])),
				// Vendor
				layout.Rigid(cellLabel(th, orDash(h.result.Vendor), widths[4])),
				// OS
				layout.Rigid(cellLabel(th, osStr(h.result), widths[5])),
				// Latency
				layout.Rigid(cellLabel(th, latencyStr(h.result.Latency), widths[6])),
				// Ports
				layout.Rigid(cellLabel(th, portsStr(h.result.OpenPorts), widths[7])),
				// Banner (flex remainder)
				layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
					lbl := material.Body2(th, bannerStr(h.result))
					lbl.TextSize = unit.Sp(10)
					lbl.MaxLines = 1
					return layout.Inset{Left: unit.Dp(4), Right: unit.Dp(4)}.Layout(gtx, lbl.Layout)
				}),
			)
		}),
	)
}

func (st *uiState) drawTableHeader(gtx layout.Context, headers []string, widths []unit.Dp) layout.Dimensions {
	th := st.th
	const h = 22
	gtx.Constraints.Min.Y = gtx.Dp(unit.Dp(h))
	gtx.Constraints.Max.Y = gtx.Dp(unit.Dp(h))
	fillRect(gtx, gtx.Constraints.Max, colHeader)

	children := make([]layout.FlexChild, len(headers))
	for i, hdr := range headers {
		i, hdr := i, hdr
		if i == len(headers)-1 || widths[i] == 0 {
			children[i] = layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
				lbl := material.Body2(th, hdr)
				lbl.Color = colHeaderText
				lbl.TextSize = unit.Sp(10)
				return layout.Inset{Left: unit.Dp(4)}.Layout(gtx, lbl.Layout)
			})
		} else {
			w := widths[i]
			children[i] = layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				gtx.Constraints.Min.X = gtx.Dp(w)
				gtx.Constraints.Max.X = gtx.Dp(w)
				lbl := material.Body2(th, hdr)
				lbl.Color = colHeaderText
				lbl.TextSize = unit.Sp(10)
				return layout.Inset{Left: unit.Dp(4)}.Layout(gtx, lbl.Layout)
			})
		}
	}
	return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx, children...)
}

// drawBcastTab is a generic renderer for mDNS / SSDP / WSD tabs.
func (st *uiState) drawBcastTab(gtx layout.Context, name string, headers []string, rows [][]string) layout.Dimensions {
	th := st.th
	widths := []unit.Dp{60, 120, 160, 160, 0}

	list := &layout.List{Axis: layout.Vertical}
	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return st.drawTableHeader(gtx, headers, widths)
		}),
		layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
			if len(rows) == 0 {
				return st.drawPlaceholder(gtx, "Listening for "+name+" traffic…")
			}
			return list.Layout(gtx, len(rows), func(gtx layout.Context, i int) layout.Dimensions {
				bg := colRowEven
				if i%2 == 1 {
					bg = colRowOdd
				}
				const rowH = 20
				gtx.Constraints.Min.Y = gtx.Dp(unit.Dp(rowH))
				return layout.Stack{}.Layout(gtx,
					layout.Stacked(func(gtx layout.Context) layout.Dimensions {
						fillRect(gtx, gtx.Constraints.Max, bg)
						row := rows[i]
						children := make([]layout.FlexChild, len(widths))
						for j := range widths {
							j := j
							val := ""
							if j < len(row) {
								val = row[j]
							}
							if j == len(widths)-1 {
								children[j] = layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
									lbl := material.Body2(th, val)
									lbl.TextSize = unit.Sp(10)
									lbl.MaxLines = 1
									return layout.Inset{Left: unit.Dp(4)}.Layout(gtx, lbl.Layout)
								})
							} else {
								w := widths[j]
								children[j] = layout.Rigid(func(gtx layout.Context) layout.Dimensions {
									return cellLabel(th, val, w)(gtx)
								})
							}
						}
						return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx, children...)
					}),
				)
			})
		}),
	)
}

func (st *uiState) drawDHCPTab(gtx layout.Context) layout.Dimensions {
	th := st.th
	headers := []string{"Time", "MAC", "IP", "Hostname", "Type"}
	widths := []unit.Dp{90, 140, 120, 160, 0}
	list := &layout.List{Axis: layout.Vertical}
	rows := st.dhcpRows

	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return st.drawTableHeader(gtx, headers, widths)
		}),
		layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
			if len(rows) == 0 {
				return st.drawPlaceholder(gtx, "Waiting for DHCP events — elevation required for passive capture")
			}
			return list.Layout(gtx, len(rows), func(gtx layout.Context, i int) layout.Dimensions {
				bg := colRowEven
				if i%2 == 1 {
					bg = colRowOdd
				}
				r := rows[i].evt
				gtx.Constraints.Min.Y = gtx.Dp(unit.Dp(20))
				return layout.Stack{}.Layout(gtx,
					layout.Stacked(func(gtx layout.Context) layout.Dimensions {
						fillRect(gtx, gtx.Constraints.Max, bg)
						return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
							layout.Rigid(cellLabel(th, r.Time.Format("15:04:05"), widths[0])),
						layout.Rigid(cellLabel(th, r.ClientMAC, widths[1])),
						layout.Rigid(cellLabel(th, r.ClientIP, widths[2])),
						layout.Rigid(cellLabel(th, r.Hostname, widths[3])),
						layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
							lbl := material.Body2(th, r.Type.String())
								lbl.TextSize = unit.Sp(10)
								return layout.Inset{Left: unit.Dp(4)}.Layout(gtx, lbl.Layout)
							}),
						)
					}),
				)
			})
		}),
	)
}

func (st *uiState) drawNetworkTab(gtx layout.Context) layout.Dimensions {
	subnets := scan.DetectLocalSubnets()
	lines := make([]string, 0, len(subnets)+2)
	lines = append(lines, "Detected local subnets:")
	for _, s := range subnets {
		lines = append(lines, "  "+s)
	}
	if len(subnets) == 0 {
		lines = append(lines, "  (none detected)")
	}
	lines = append(lines, "", "Service status: "+st.svcStatus)

	th := st.th
	list := &layout.List{Axis: layout.Vertical}
	return layout.Inset{Top: unit.Dp(12), Bottom: unit.Dp(12), Left: unit.Dp(12), Right: unit.Dp(12)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		return list.Layout(gtx, len(lines), func(gtx layout.Context, i int) layout.Dimensions {
			return material.Body2(th, lines[i]).Layout(gtx)
		})
	})
}

func (st *uiState) drawStatusBar(gtx layout.Context) layout.Dimensions {
	th := st.th
	const h = 22
	gtx.Constraints.Min.Y = gtx.Dp(unit.Dp(h))
	gtx.Constraints.Max.Y = gtx.Dp(unit.Dp(h))
	fillRect(gtx, gtx.Constraints.Max, colStatusBar)

	listenerStatus := "mDNS · SSDP · WSD · DHCP: listening"
	return layout.Inset{Left: unit.Dp(8), Right: unit.Dp(8)}.Layout(gtx,
		func(gtx layout.Context) layout.Dimensions {
			return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
				layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
					lbl := material.Body2(th, listenerStatus)
					lbl.Color = colStatusText
					lbl.TextSize = unit.Sp(10)
					return lbl.Layout(gtx)
				}),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					lbl := material.Body2(th, st.svcStatus)
					lbl.Color = colStatusText
					lbl.TextSize = unit.Sp(10)
					return lbl.Layout(gtx)
				}),
			)
		},
	)
}

func (st *uiState) drawPlaceholder(gtx layout.Context, msg string) layout.Dimensions {
	th := st.th
	return layout.Center.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		lbl := material.Body1(th, msg)
		lbl.Color = colPending
		return lbl.Layout(gtx)
	})
}

// ---------------------------------------------------------------------------
// Broadcast tab data helpers
// ---------------------------------------------------------------------------

func (st *uiState) mdnsRowData() [][]string {
	rows := make([][]string, len(st.mdnsRows))
	for i, r := range st.mdnsRows {
		rows[i] = []string{r.source, r.ip, r.name, r.svcType, r.details}
	}
	return rows
}

func (st *uiState) ssdpRowData() [][]string {
	rows := make([][]string, len(st.ssdpRows))
	for i, r := range st.ssdpRows {
		rows[i] = []string{r.source, r.ip, r.name, r.svcType, r.details}
	}
	return rows
}

func (st *uiState) wsdRowData() [][]string {
	rows := make([][]string, len(st.wsdRows))
	for i, r := range st.wsdRows {
		rows[i] = []string{r.source, r.ip, r.name, r.svcType, r.details}
	}
	return rows
}

// ---------------------------------------------------------------------------
// Layout helpers
// ---------------------------------------------------------------------------

func cellLabel(th *material.Theme, s string, w unit.Dp) layout.Widget {
	return func(gtx layout.Context) layout.Dimensions {
		gtx.Constraints.Min.X = gtx.Dp(w)
		gtx.Constraints.Max.X = gtx.Dp(w)
		lbl := material.Body2(th, s)
		lbl.TextSize = unit.Sp(10)
		lbl.MaxLines = 1
		return layout.Inset{Left: unit.Dp(4), Right: unit.Dp(2)}.Layout(gtx, lbl.Layout)
	}
}

func spacer(dp unit.Dp) layout.Widget {
	return func(gtx layout.Context) layout.Dimensions {
		return layout.Dimensions{Size: image.Point{X: gtx.Dp(dp)}}
	}
}

func fillRect(gtx layout.Context, size image.Point, col color.NRGBA) {
	defer clip.Rect{Max: size}.Push(gtx.Ops).Pop()
	paint.ColorOp{Color: col}.Add(gtx.Ops)
	paint.PaintOp{}.Add(gtx.Ops)
}

func drawDivider(gtx layout.Context, top bool) {
	h := gtx.Constraints.Max.Y
	if top {
		h = 1
	}
	r := clip.Rect{Max: image.Point{X: gtx.Constraints.Max.X, Y: 1}}
	if !top {
		r = clip.Rect{Min: image.Point{Y: h - 1}, Max: image.Point{X: gtx.Constraints.Max.X, Y: h}}
	}
	defer r.Push(gtx.Ops).Pop()
	paint.ColorOp{Color: colDivider}.Add(gtx.Ops)
	paint.PaintOp{}.Add(gtx.Ops)
}

// ---------------------------------------------------------------------------
// Result formatting helpers
// ---------------------------------------------------------------------------

func hostname(r scan.Result) string {
	if r.Hostname != "" {
		return r.Hostname
	}
	if r.NetBIOS != "" {
		return r.NetBIOS + " (NetBIOS)"
	}
	return "—"
}

func macStr(mac net.HardwareAddr) string {
	if mac == nil {
		return "—"
	}
	return mac.String()
}

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

func osStr(r scan.Result) string {
	s := string(r.OS)
	if s == "" {
		return "—"
	}
	return s
}

func latencyStr(d time.Duration) string {
	if d == 0 {
		return "—"
	}
	return d.Round(time.Millisecond).String()
}

func portsStr(ports []int) string {
	if len(ports) == 0 {
		return "—"
	}
	parts := make([]string, len(ports))
	for i, p := range ports {
		parts[i] = fmt.Sprintf("%d", p)
	}
	return strings.Join(parts, ", ")
}

func bannerStr(r scan.Result) string {
	var parts []string
	for _, b := range []struct{ label, val string }{
		{"SSH", r.Banner.SSH}, {"HTTP", r.Banner.HTTP}, {"HTTPS", r.Banner.HTTPS},
		{"FTP", r.Banner.FTP}, {"SMTP", r.Banner.SMTP},
	} {
		if b.val != "" {
			parts = append(parts, b.label+": "+b.val)
		}
	}
	if r.SNMP != nil && (r.SNMP.SysName != "" || r.SNMP.SysDescr != "") {
		s := r.SNMP.SysDescr
		if r.SNMP.SysName != "" {
			s = r.SNMP.SysName + ": " + s
		}
		parts = append(parts, "SNMP: "+s)
	}
	if len(parts) == 0 {
		return "—"
	}
	return strings.Join(parts, "  |  ")
}
