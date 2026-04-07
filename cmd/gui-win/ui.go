//go:build windows

package guiwin

import (
	"context"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/demicloud/net-scope/internal/config"
	"github.com/demicloud/net-scope/internal/sweep"
)

// ---------------------------------------------------------------------------
// Global UI handles / resources
// ---------------------------------------------------------------------------

// Elevation bar status brushes — created in createControls, used in WM_CTLCOLORSTATIC.
// Win32 COLORREF is 0x00BBGGRR (low byte = red).
var (
	brushElevGrey  HBRUSH // service not running  — light grey  RGB(235,235,235)
	brushElevAmber HBRUSH // running, unelevated  — light amber RGB(255,243,205)
	brushElevGreen HBRUSH // running, elevated    — light green RGB(212,237,218)
)

var (
	appFont        HFONT // Segoe UI 9pt — shared by main window and all dialogs
	hwndMain       HWND
	headerHwnd     HWND  // header control of hwndList, for right-click detection
	// Elevation bar (top strip)
	hwndElevLabel  HWND // service status label
	hwndServiceBtn HWND // "Elevate sweep service" button (hidden when already elevated)
	// Scan bar (shown only when Hosts tab is active)
	hwndTarget          HWND
	hwndDetect          HWND // "⟲" detect local subnet button
	hwndScan            HWND // toggle: "Scan" at rest, "Stop" while scanning
	// Content panes
	hwndList            HWND
	hwndListPlaceholder HWND // empty-state overlay for Scanner tab
	hwndMDNSPlaceholder HWND // empty-state overlay for mDNS tab
	hwndSSDPPlaceholder HWND // empty-state overlay for SSDP tab
	hwndWSDPlaceholder  HWND // empty-state overlay for WSD tab
	hwndDHCPPlaceholder HWND // empty-state overlay for DHCP tab
	hwndListMDNS   HWND // mDNS tab
	hwndListSSDP   HWND // SSDP tab
	hwndListWSD    HWND // WS-Discovery tab
	hwndListDHCP   HWND // DHCP tab
	hwndListNetwork HWND // Network tab — live broadcast stats
	hwndListHealth        HWND // Scan Report tab
	hwndHealthPlaceholder HWND // empty-state overlay for Scan Report tab
	scanEverCompleted     bool // true once the first scan has completed
	hwndTabCtrl    HWND
	hwndStatus     HWND
)

// ---------------------------------------------------------------------------
// Scan state
// ---------------------------------------------------------------------------

var (
	scanCancel context.CancelFunc
	scanMu     sync.Mutex

	// Cross-thread result queue: scan goroutine appends, UI thread reads.
	pendingResults []sweep.Result
	pendingMu      sync.Mutex
	liveCount      int
	lastStats      sweep.ScanStats // populated after scan completes
	scanStartTime  time.Time       // set when scan begins, used for duration metric
	listHasHosts  bool            // true once ≥1 alive host found in current/last scan
	isScanning    bool            // true while a scan is in progress (UI thread only)

	// ipRowMap maps IP string → row index in hwndList.
	// Written on the UI thread (startScan), read on the UI thread (WM_SCAN_RESULT).
	ipRowMap    map[string]int32
	// rowResultMap maps ListView row index → scan Result, for right-click menus.
	rowResultMap map[int32]sweep.Result
)

// ---------------------------------------------------------------------------
// Background broadcast listener state
// ---------------------------------------------------------------------------

var (
	bcastCancel    context.CancelFunc
	bcastMu        sync.Mutex
	bcastCount     int // total services received since app start
	bcastMDNS      int // mDNS entries
	bcastSSDP      int // SSDP entries
	bcastWSD       int // WSD entries
	bcastDHCP      int // DHCP entries
	pendingBcast   []bcastEntry
	pendingBcastMu sync.Mutex

	// DHCP event queue: service goroutine appends, UI thread reads via WM_DHCP_EVENT.
	pendingDHCP   []sweep.DHCPEvent
	pendingDHCPMu sync.Mutex

	// Host enrichment queue: background goroutines append NetBIOS names / ARP MACs
	// for existing Hosts rows; UI thread processes via WM_HOST_ENRICH.
	pendingEnriches []enrichEvent
	pendingEnrichMu sync.Mutex

	// arpPollCancel cancels the periodic ARP table polling goroutine.
	arpPollCancel context.CancelFunc

	// hostRegistry accumulates data about every host seen across all scans
	// and broadcast events. Written and read only on the UI thread.
	hostRegistry map[string]*hostEntry
)

// ensureHostEntry returns the hostEntry for ip, creating it if needed.
func ensureHostEntry(ip string) *hostEntry {
	if hostRegistry == nil {
		hostRegistry = make(map[string]*hostEntry)
	}
	e, ok := hostRegistry[ip]
	if !ok {
		e = &hostEntry{IP: ip, FirstSeen: time.Now()}
		hostRegistry[ip] = e
	}
	return e
}

// allHostIPs returns all known IPs from the registry, sorted numerically.
func allHostIPs() []string {
	ips := make([]string, 0, len(hostRegistry))
	for ip := range hostRegistry {
		ips = append(ips, ip)
	}
	sort.Slice(ips, func(i, j int) bool {
		ai := net.ParseIP(ips[i]).To4()
		aj := net.ParseIP(ips[j]).To4()
		if ai == nil || aj == nil {
			return ips[i] < ips[j]
		}
		for k := 0; k < 4; k++ {
			if ai[k] != aj[k] {
				return ai[k] < aj[k]
			}
		}
		return false
	})
	return ips
}

// enrichEvent carries a NetBIOS name and/or MAC for an existing Hosts row.
type enrichEvent struct {
	ip      string
	netbios string
	mac     net.HardwareAddr
}

// hostEntry is the persistent record for a host seen across any source.
type hostEntry struct {
	IP           string
	FirstSeen    time.Time
	LastSeen     time.Time
	Result       sweep.Result      // latest scan data (zero-value for broadcast-only hosts)
	HasResult    bool              // true once a scan result has been recorded
	DHCPEvents   []sweep.DHCPEvent // all DHCP packets observed for this IP
	ExtraServices []sweep.ServiceInfo // broadcast services not yet in Result.Services
}

type bcastEntry struct {
	ip  string
	svc sweep.ServiceInfo
}

func startBroadcastListener() {
	bcastMu.Lock()
	defer bcastMu.Unlock()
	if bcastCancel != nil {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	bcastCancel = cancel
	go func() {
		bl, err := time.ParseDuration(appConfig.Scan.BroadcastListen)
		if err != nil || bl <= 0 {
			bl = 3 * time.Second
		}
		sweep.ListenBroadcast(ctx, bl, func(ip string, svc sweep.ServiceInfo) {
			pendingBcastMu.Lock()
			idx := len(pendingBcast)
			pendingBcast = append(pendingBcast, bcastEntry{ip, svc})
			pendingBcastMu.Unlock()
			postMessage(hwndMain, WM_BCAST_SVC, uintptr(idx), 0)
		})
	}()
}

func stopBroadcastListener() {
	bcastMu.Lock()
	defer bcastMu.Unlock()
	if bcastCancel != nil {
		bcastCancel()
		bcastCancel = nil
	}
}

// kickNetBIOSProbe sends a unicast NetBIOS NAME_STATUS query to ip in the
// background. On success, WM_HOST_ENRICH is posted to update the Hosts row.
func kickNetBIOSProbe(hwnd HWND, ip string) {
	go func() {
		parsed := net.ParseIP(ip)
		if parsed == nil {
			return
		}
		name := sweep.ProbeNetBIOS(parsed, 2*time.Second)
		if name == "" {
			return
		}
		pendingEnrichMu.Lock()
		idx := len(pendingEnriches)
		pendingEnriches = append(pendingEnriches, enrichEvent{ip: ip, netbios: name})
		pendingEnrichMu.Unlock()
		postMessage(hwnd, WM_HOST_ENRICH, uintptr(idx), 0)
	}()
}

// startARPPoll begins a background goroutine that reads the Windows ARP table
// every 5 s and posts WM_HOST_ENRICH for each entry. The UI thread skips
// entries for unknown IPs and rows that already have a MAC.
func startARPPoll(hwnd HWND) {
	stopARPPoll()
	ctx, cancel := context.WithCancel(context.Background())
	arpPollCancel = cancel
	go func() {
		t := time.NewTicker(5 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				for ip, mac := range sweep.ReadARPTable() {
					macCopy := mac
					pendingEnrichMu.Lock()
					idx := len(pendingEnriches)
					pendingEnriches = append(pendingEnriches, enrichEvent{ip: ip, mac: macCopy})
					pendingEnrichMu.Unlock()
					postMessage(hwnd, WM_HOST_ENRICH, uintptr(idx), 0)
				}
			}
		}
	}()
}

func stopARPPoll() {
	if arpPollCancel != nil {
		arpPollCancel()
		arpPollCancel = nil
	}
}

// ---------------------------------------------------------------------------
// Layout constants
// ---------------------------------------------------------------------------

const (
	toolbarH = 38 // legacy constant (kept for dialogs that reference it)
	elevBarH = 32 // elevation status strip at very top
	scanBarH = 36 // scan controls bar (shown only on Hosts tab)
	tabCtrlH = 26 // height of the tab row
)

// ---------------------------------------------------------------------------
// WndProc
// ---------------------------------------------------------------------------

var wndProcCallback = syscall.NewCallback(func(hwnd, msg, wParam, lParam uintptr) uintptr {
	switch uint32(msg) {
	case WM_DPICHANGED:
		// wParam HIWORD = new DPI. lParam = suggested window rect at new DPI.
		newDPI := uint32(hiword(wParam))
		if newDPI == 0 {
			newDPI = 96
		}
		currentDPI = newDPI
		// Recreate the font at the new DPI and push it to all children.
		if appFont != 0 {
			deleteObject(uintptr(appFont))
		}
		appFont = createUIFont(currentDPI)
		setFontAllChildren(HWND(hwnd), appFont)
		// Move the window to the rect Windows suggests (avoids text blurriness).
		rect := (*RECT)(unsafe.Pointer(lParam)) //nolint:govet
		setWindowPos(HWND(hwnd), 0, rect.Left, rect.Top,
			rect.Right-rect.Left, rect.Bottom-rect.Top,
			SWP_NOZORDER|SWP_NOACTIVATE)
		return 0

	case WM_CTLCOLORSTATIC:
		// Colour the elevation status strip based on service state.
		if HWND(lParam) == hwndElevLabel && brushElevGrey != 0 {
			hdc := wParam
			var bg, fg uint32
			var brush HBRUSH
			switch {
			case serviceRunning() && serviceElevated:
				bg, fg, brush = 0x00DAEDD4, 0x00245715, brushElevGreen // green
			case serviceRunning():
				bg, fg, brush = 0x00CDF3FF, 0x00046485, brushElevAmber // amber
			default:
				bg, fg, brush = 0x00EBEBEB, 0x00505050, brushElevGrey  // grey
			}
			setBkMode(hdc, OPAQUE)
			setTextColor(hdc, fg)
			setBkColor(hdc, bg)
			return uintptr(brush)
		}
		// Placeholder text gets gray color, white background matching the listview.
		if HWND(lParam) == hwndListPlaceholder ||
			HWND(lParam) == hwndMDNSPlaceholder ||
			HWND(lParam) == hwndSSDPPlaceholder ||
			HWND(lParam) == hwndWSDPlaceholder ||
			HWND(lParam) == hwndDHCPPlaceholder {
			setBkMode(wParam, TRANSPARENT)
			setTextColor(wParam, 0x00999999)
			return uintptr(getSysColorBrush(COLOR_WINDOW))
		}
		// Any other STATIC on the main window (e.g. "Target:" label) should
		// blend with the COLOR_WINDOW background, not get the default
		// COLOR_BTNFACE gray that defWindowProc would return.
		setBkMode(wParam, TRANSPARENT)
		return uintptr(getSysColorBrush(COLOR_WINDOW))

	case WM_SERVICE_UP:
		setWindowText(hwndElevLabel, statusForService())
		if serviceElevated {
			enableWindow(hwndServiceBtn, false)
			// Start passive DHCP capture in the elevated service.
			startDHCPCapture(HWND(hwnd))
		}
		updateNetworkTab()
		return 0

	case WM_SERVICE_DOWN:
		setWindowText(hwndElevLabel, "Service: not running")
		return 0

	case WM_DHCP_EVENT:
		pendingDHCPMu.Lock()
		var evt sweep.DHCPEvent
		if int(wParam) < len(pendingDHCP) {
			evt = pendingDHCP[int(wParam)]
		}
		pendingDHCPMu.Unlock()
		listViewAddDHCPRow(hwndListDHCP, evt)
		if bcastDHCP == 0 {
			showWindow(hwndDHCPPlaceholder, SW_HIDE)
		}
		bcastDHCP++
		// Cross-enrich the Hosts tab: if the DHCP IP matches a scanned row,
		// fill in hostname (opt 12) and/or MAC (chaddr) if currently blank.
		enrichIP := evt.OfferedIP
		if enrichIP == "" || enrichIP == "0.0.0.0" {
			enrichIP = evt.ClientIP
		}
		if enrichIP != "" && enrichIP != "0.0.0.0" {
			// Registry: store DHCP event regardless of whether IP is in Hosts tab.
			en := ensureHostEntry(enrichIP)
			en.LastSeen = time.Now()
			en.DHCPEvents = append(en.DHCPEvents, evt)
			if _, inHosts := ipRowMap[enrichIP]; inHosts {
				var parsedMAC net.HardwareAddr
				if evt.ClientMAC != "" {
					parsedMAC, _ = net.ParseMAC(evt.ClientMAC)
				}
				if evt.Hostname != "" || parsedMAC != nil {
					pendingEnrichMu.Lock()
					idx := len(pendingEnriches)
					pendingEnriches = append(pendingEnriches, enrichEvent{
						ip:      enrichIP,
						netbios: evt.Hostname,
						mac:     parsedMAC,
					})
					pendingEnrichMu.Unlock()
					postMessage(HWND(hwnd), WM_HOST_ENRICH, uintptr(idx), 0)
				}
				if evt.Hostname == "" {
					kickNetBIOSProbe(HWND(hwnd), enrichIP)
				}
			}
		}
		return 0

	case WM_CREATE:
		createControls(HWND(hwnd))
		if noConfigFile {
			postMessage(HWND(hwnd), WM_FIRST_RUN, 0, 0)
		}
		startBroadcastListener()
		// Start the sweep service immediately (user-level, no UAC).
		go startService(HWND(hwnd))
		return 0

	case WM_SIZE:
		resizeControls(HWND(hwnd), lParam)
		return 0

	case WM_NOTIFY:
		// lParam points to Windows-managed memory; the GC will not move it.
		// go vet flags uintptr→unsafe.Pointer but this is a known false positive
		// for syscall.NewCallback parameters that carry Windows system pointers.
		hdr := (*NMHDR)(unsafe.Pointer(lParam)) //nolint:govet
		if hdr.IdFrom == IDC_TABS && hdr.Code == TCN_SELCHANGE {
			tab := int32(sendMessage(hwndTabCtrl, TCM_GETCURSEL, 0, 0))
			// Hide all panes first.
			showWindow(hwndList, SW_HIDE)
			showWindow(hwndListPlaceholder, SW_HIDE)
			showWindow(hwndListMDNS, SW_HIDE)
			showWindow(hwndMDNSPlaceholder, SW_HIDE)
			showWindow(hwndListSSDP, SW_HIDE)
			showWindow(hwndSSDPPlaceholder, SW_HIDE)
			showWindow(hwndListWSD, SW_HIDE)
			showWindow(hwndWSDPlaceholder, SW_HIDE)
			showWindow(hwndListDHCP, SW_HIDE)
			showWindow(hwndDHCPPlaceholder, SW_HIDE)
			showWindow(hwndListNetwork, SW_HIDE)
			showWindow(hwndListHealth, SW_HIDE)
			showWindow(hwndHealthPlaceholder, SW_HIDE)
			// Show/hide scan bar and reposition Hosts listview accordingly.
			// On Hosts tab the scan bar is visible and the list sits below it;
			// on all other tabs the list fills from just below the tab strip.
			if tab == 0 {
				showWindow(hwndTarget, SW_SHOW)
				showWindow(hwndDetect, SW_SHOW)
				showWindow(hwndScan, SW_SHOW)

				// Ensure Hosts list is repositioned to account for scan bar.
				r := getClientRect(hwndMain)
				statusR := getClientRect(hwndStatus)
				statusH := statusR.Bottom - statusR.Top
				hostsTop := scale(elevBarH + tabCtrlH + scanBarH)
				listH := (r.Bottom - r.Top) - hostsTop - statusH
				if listH < 0 {
					listH = 0
				}
				moveWindow(hwndList, 0, hostsTop, r.Right-r.Left, listH)
				moveWindow(hwndListPlaceholder, 0, hostsTop+(listH-scale(20))/2, r.Right-r.Left, scale(20))
				showWindow(hwndList, SW_SHOW)
				if !isScanning && !listHasHosts {
					showWindow(hwndListPlaceholder, SW_SHOW)
				}
			} else {
				showWindow(hwndTarget, SW_HIDE)
				showWindow(hwndDetect, SW_HIDE)
				showWindow(hwndScan, SW_HIDE)
				switch tab {
				case 1:
					showWindow(hwndListMDNS, SW_SHOW)
					if bcastMDNS == 0 {
						showWindow(hwndMDNSPlaceholder, SW_SHOW)
					}
				case 2:
					showWindow(hwndListSSDP, SW_SHOW)
					if bcastSSDP == 0 {
						showWindow(hwndSSDPPlaceholder, SW_SHOW)
					}
				case 3:
					showWindow(hwndListWSD, SW_SHOW)
					if bcastWSD == 0 {
						showWindow(hwndWSDPlaceholder, SW_SHOW)
					}
				case 4:
					showWindow(hwndListDHCP, SW_SHOW)
					if bcastDHCP == 0 {
						showWindow(hwndDHCPPlaceholder, SW_SHOW)
					}
				case 5:
					showWindow(hwndListNetwork, SW_SHOW)
				case 6:
					showWindow(hwndListHealth, SW_SHOW)
					if !scanEverCompleted {
						showWindow(hwndHealthPlaceholder, SW_SHOW)
					}
				}
			}
		}
		// Column header click → sort (all tabs).
		if hdr.Code == LVN_COLUMNCLICK {
			nm := (*NMLISTVIEW)(unsafe.Pointer(lParam)) //nolint:govet
			if handleListColumnClick(hdr.IdFrom, nm.ISubItem) {
				return 0
			}
		}
		// Right-click on any listview header → Edit Columns menu.
		if hdr.Code == NM_RCLICK {
			if info, ok := headerInfos[HWND(hdr.HwndFrom)]; ok {
				pt := getCursorPos()
				hmenu := createPopupMenu()
				appendMenu(hmenu, MF_STRING, IDM_HEADER_EDIT_COLS, "Edit Columns…")
				cmd := trackPopupMenu(hmenu, TPM_RIGHTBUTTON|TPM_RETURNCMD, pt.X, pt.Y, HWND(hwnd))
				destroyMenu(hmenu)
				if int32(cmd) == IDM_HEADER_EDIT_COLS {
					showEditColumnsDialog(HWND(hwnd), info.hwndLV, info.colTitles, info.colVis, info.defWidths)
				}
				return 0
			}
		}
		// Double-click on host list → host detail dialog.
		if hdr.IdFrom == IDC_LIST && hdr.Code == NM_DBLCLK {
			row := int32(sendMessage(hwndList, LVM_GETNEXTITEM, ^uintptr(0), LVNI_SELECTED))
			if row >= 0 {
				ip := listViewGetCellText(hwndList, row, colIP)
				if ip != "" {
					showHostDetailDialog(HWND(hwnd), ip)
				}
			}
			return 0
		}
		// Double-click on mDNS / SSDP / WSD lists → host detail dialog (col 0 = IP).
		if (hdr.IdFrom == IDC_LIST_MDNS || hdr.IdFrom == IDC_LIST_SSDP || hdr.IdFrom == IDC_LIST_WSD) &&
			hdr.Code == NM_DBLCLK {
			var hwndSrc HWND
			switch hdr.IdFrom {
			case IDC_LIST_MDNS:
				hwndSrc = hwndListMDNS
			case IDC_LIST_SSDP:
				hwndSrc = hwndListSSDP
			case IDC_LIST_WSD:
				hwndSrc = hwndListWSD
			}
			row := int32(sendMessage(hwndSrc, LVM_GETNEXTITEM, ^uintptr(0), LVNI_SELECTED))
			if row >= 0 {
				ip := listViewGetCellText(hwndSrc, row, 0)
				if ip != "" {
					showHostDetailDialog(HWND(hwnd), ip)
				}
			}
			return 0
		}
		// Double-click on DHCP list → host detail dialog.
		// Prefer Offered IP (col 6), fall back to Client IP (col 4).
		if hdr.IdFrom == IDC_LIST_DHCP && hdr.Code == NM_DBLCLK {
			row := int32(sendMessage(hwndListDHCP, LVM_GETNEXTITEM, ^uintptr(0), LVNI_SELECTED))
			if row >= 0 {
				ip := listViewGetCellText(hwndListDHCP, row, 6) // Offered IP
				if ip == "" || ip == "—" {
					ip = listViewGetCellText(hwndListDHCP, row, 4) // Client IP
				}
				if ip != "" && ip != "—" {
					showHostDetailDialog(HWND(hwnd), ip)
				}
			}
			return 0
		}
		// Right-click on host list → context menu.
		if hdr.IdFrom == IDC_LIST && hdr.Code == NM_RCLICK {
			pt := getCursorPos()
			// Convert screen coords to list-view client coords for hit-test.
			cpt := POINT{X: pt.X, Y: pt.Y}
			procScreenToClient.Call(uintptr(hwndList), uintptr(unsafe.Pointer(&cpt)))
			htInfo := LVHITTESTINFO{Pt: cpt}
			row := int32(sendMessage(hwndList, LVM_HITTEST, 0, uintptr(unsafe.Pointer(&htInfo))))
			if row >= 0 {
				if r, ok := rowResultMap[row]; ok {
					showHostContextMenu(HWND(hwnd), r, pt.X, pt.Y)
				}
			}
			return 0
		}
		// Right-click on mDNS / SSDP / WSD / DHCP lists → copy menu.
		if (hdr.IdFrom == IDC_LIST_MDNS || hdr.IdFrom == IDC_LIST_SSDP ||
			hdr.IdFrom == IDC_LIST_WSD || hdr.IdFrom == IDC_LIST_DHCP) && hdr.Code == NM_RCLICK {
			hwndSrc, numCols, headers := listViewInfoFor(hdr.IdFrom)
			if hwndSrc == 0 {
				return 0
			}
			pt := getCursorPos()
			cpt := POINT{X: pt.X, Y: pt.Y}
			procScreenToClient.Call(uintptr(hwndSrc), uintptr(unsafe.Pointer(&cpt)))
			htInfo := LVHITTESTINFO{Pt: cpt}
			sendMessage(hwndSrc, LVM_HITTEST, 0, uintptr(unsafe.Pointer(&htInfo)))
			// Use selected rows; fall back to the hovered row if nothing is selected.
			rows := listViewGetSelectedRows(hwndSrc)
			if len(rows) == 0 && htInfo.IItem >= 0 {
				rows = []int32{htInfo.IItem}
			}
			menu := createPopupMenu()
			if len(rows) > 0 {
				appendCopyAsSubmenu(menu)
			}
			hasRaw := hdr.IdFrom != IDC_LIST_DHCP
			if hasRaw && htInfo.IItem >= 0 {
				if len(rows) > 0 {
					appendMenu(menu, MF_SEPARATOR, 0, "")
				}
				appendMenu(menu, MF_STRING, IDM_BCAST_COPY_RAW, "Copy raw data")
			}
			cmd := trackPopupMenu(menu, TPM_LEFTALIGN|TPM_TOPALIGN|TPM_RETURNCMD, pt.X, pt.Y, HWND(hwnd))
			destroyMenu(menu)
			if !handleCopyAsCmd(HWND(hwnd), hwndSrc, cmd, rows, numCols, headers) {
				switch cmd {
				case IDM_BCAST_COPY_RAW:
					switch hdr.IdFrom {
					case IDC_LIST_MDNS:
						copyToClipboard(HWND(hwnd), mdnsRawClipboardText(hwndSrc, rows))
					case IDC_LIST_WSD:
						seen := map[string]bool{}
						var parts []string
						for _, r := range rows {
							ip := listViewGetCellText(hwndSrc, r, 0)
							if !seen[ip] {
								seen[ip] = true
								parts = append(parts, getWSDRawText(ip))
							}
						}
						copyToClipboard(HWND(hwnd), strings.Join(parts, "\n---\n"))
					case IDC_LIST_SSDP:
						seen := map[string]bool{}
						var parts []string
						for _, r := range rows {
							ip := listViewGetCellText(hwndSrc, r, 0)
							if !seen[ip] {
								seen[ip] = true
								parts = append(parts, getSSDPRawText(ip))
							}
						}
						copyToClipboard(HWND(hwnd), strings.Join(parts, "\n---\n"))
					}
				}
			}
			return 0
		}
		// Ctrl+A / Ctrl+C in any ListView.
		if hdr.Code == LVN_KEYDOWN {
			kd := (*NMLVKEYDOWN)(unsafe.Pointer(lParam))
			if getKeyState(VK_CONTROL) < 0 {
				switch kd.WVKey {
				case VK_KEY_A:
					listViewSelectAll(HWND(hdr.HwndFrom))
					return 0
				case VK_KEY_C:
					hw, nc, hdrs := listViewInfoFor(hdr.IdFrom)
					if hw != 0 {
						rows := listViewGetSelectedRows(hw)
						handleCopyAsCmd(HWND(hwnd), hw, IDM_COPY_AS_TSV, rows, nc, hdrs)
					}
					return 0
				}
			}
		}
		// LVN_KEYDOWN is handled above; fall through to custom draw.
		// Custom draw: alternating row backgrounds, dim dead rows, colour ●/✕ status dot.
		if hdr.IdFrom == IDC_LIST && hdr.Code == NM_CUSTOMDRAW {
			cd := (*NMLVCUSTOMDRAW)(unsafe.Pointer(lParam)) //nolint:govet
			switch cd.DwDrawStage {
			case CDDS_PREPAINT:
				return CDRF_NOTIFYITEMDRAW
			case CDDS_ITEMPREPAINT:
				row := int32(cd.DwItemSpec)
				if row%2 == 0 {
					cd.ClrTextBk = 0x00FFFFFF // white
				} else {
					cd.ClrTextBk = 0x00F5F5F5 // very light gray
				}
				// Request per-subitem notifications to colour the status column.
				return CDRF_NOTIFYITEMDRAW | CDRF_NEWFONT
			case CDDS_SUBITEM | CDDS_ITEMPREPAINT:
				// For the status column (col 0) Win32 ignores LVCFMT_CENTER, so we
				// draw the symbol centred ourselves and suppress default rendering.
				if int32(cd.ISubItem) == colStatus {
					row := int32(cd.DwItemSpec)
					// Choose symbol and colour.
					text, color := "…", uint32(0x00AAAAAA)
					if r, ok := rowResultMap[row]; ok {
						if r.Alive {
							text, color = "●", 0x0028A028
						} else {
							text, color = "✕", 0x001E1EC8
						}
					}
					// Alternating row background (match CDDS_ITEMPREPAINT logic).
					bgColor := uint32(0x00FFFFFF)
					if row%2 != 0 {
						bgColor = 0x00F5F5F5
					}
					bg := createSolidBrush(bgColor)
					rc := cd.Rc
					fillRect(cd.Hdc, &rc, bg)
					deleteObject(uintptr(bg))
					setBkMode(cd.Hdc, TRANSPARENT)
					setTextColor(cd.Hdc, color)
					drawText(cd.Hdc, text, &rc, DT_CENTER|DT_VCENTER|DT_SINGLELINE|DT_NOPREFIX)
					return CDRF_SKIPDEFAULT
				}
				return CDRF_NEWFONT
			}
		}
		return 0

	case WM_COMMAND:
		switch loword(wParam) {
		case IDC_SERVICE_BTN:
			// Spawn elevated service via UAC. Existing service is stopped first.
			go elevateService(HWND(hwnd))
		case IDC_DETECT:
			detectSubnet(HWND(hwnd))
		case IDC_SCAN:
			if isScanning {
				stopScan()
				// Reset UI immediately — don't wait for WM_SCAN_COMPLETE,
				// which may be delayed (especially for service scans).
				isScanning = false
				setWindowText(hwndScan, "Scan")
				setStatusPart(2, "Scan stopped")
			} else {
				startScan(HWND(hwnd))
			}
		case IDM_FILE_EXIT:
			stopScan()
			postQuitMessage(0)
		case IDM_FILE_EXPORT_JSON:
			exportResults(HWND(hwnd), "json")
		case IDM_FILE_EXPORT_CSV:
			exportResults(HWND(hwnd), "csv")
		case IDM_OPT_SETTINGS:
			showSettingsDialog(HWND(hwnd))
		case IDM_OPT_DATABASES:
			showDatabasesDialog(HWND(hwnd))
		case IDM_HOSTS_VIEW_ALL:
			showAllHostsDialog(HWND(hwnd))
		case IDM_HOSTS_VIEW_HOST:
			showPickHostDialog(HWND(hwnd))
		case IDM_HELP_FAQ:
			showFAQDialog(HWND(hwnd))
		case IDM_HELP_VERSION:
			showVersionDialog(HWND(hwnd))
		case IDM_HELP_ABOUT:
			showAboutDialog(HWND(hwnd))
		case IDM_HELP_CRASHLOG:
			path := crashLogPath()
			if _, err := os.Stat(path); os.IsNotExist(err) {
				messageBox(HWND(hwnd), "No crash log found.\n\nIf the app closes unexpectedly, a log will be written to:\n"+path, "Crash Log", 0)
			} else {
				shellExecute(HWND(hwnd), "open", "notepad.exe", path, "", SW_SHOW)
			}
		}
		return 0

	case WM_FIRST_RUN:
		// No config file was found at startup.  Ask where (if anywhere) to
		// save one, then write the current defaults there.  Settings can be
		// adjusted afterwards via Options → Settings.
		appDataPath := config.ConfigPath()
		exePath := config.ExeLocalPath()
		savePath := showConfigLocationDialog(HWND(hwnd), appDataPath, exePath)
		if savePath != "" {
			_ = config.SaveTo(appConfig, savePath)
		}
		return 0

	case WM_BCAST_SVC:
		pendingBcastMu.Lock()
		var e bcastEntry
		if int(wParam) < len(pendingBcast) {
			e = pendingBcast[int(wParam)]
		}
		pendingBcastMu.Unlock()
		if e.ip != "" {
			switch e.svc.Source {
			case "ssdp":
				listViewAddSSDPRow(hwndListSSDP, e.ip, e.svc)
				if bcastSSDP == 0 {
					showWindow(hwndSSDPPlaceholder, SW_HIDE)
				}
				bcastSSDP++
			case "wsd":
				listViewAddWSDRow(hwndListWSD, e.ip, e.svc)
				if bcastWSD == 0 {
					showWindow(hwndWSDPlaceholder, SW_HIDE)
				}
				bcastWSD++
			default:
				listViewAddMDNSRow(hwndListMDNS, e.ip, e.svc)
				if bcastMDNS == 0 {
					showWindow(hwndMDNSPlaceholder, SW_HIDE)
				}
				bcastMDNS++
			}
			bcastCount++
			setStatusPart(1, fmt.Sprintf("Broadcast: %d service(s)", bcastCount))
			updateNetworkTab()
			// Registry: append service to the host's ExtraServices list.
			en := ensureHostEntry(e.ip)
			en.LastSeen = time.Now()
			en.ExtraServices = append(en.ExtraServices, e.svc)
		}
		return 0

	case WM_SCAN_RESULT:
		pendingMu.Lock()
		r := pendingResults[int(wParam)]
		pendingMu.Unlock()

		ipStr := r.IP.String()
		// Always update the registry with the latest scan data.
		{
			en := ensureHostEntry(ipStr)
			en.LastSeen = time.Now()
			en.Result = r
			en.HasResult = true
		}
		if row, found := ipRowMap[ipStr]; found {
			listViewUpdateRow(hwndList, row, r)
			rowResultMap[row] = r
			if r.Alive {
				liveCount++
				if !listHasHosts {
					listHasHosts = true
					showWindow(hwndListPlaceholder, SW_HIDE)
				}
				setStatusPart(0, fmt.Sprintf("Hosts: found %d", liveCount))
			}
		} else if r.Alive {
			// Broadcast-only or out-of-range host.
			row := listViewInsertPendingRow(hwndList, ipStr)
			ipRowMap[ipStr] = row
			listViewUpdateRow(hwndList, row, r)
			rowResultMap[row] = r
			liveCount++
			if !listHasHosts {
				listHasHosts = true
				showWindow(hwndListPlaceholder, SW_HIDE)
			}
			setStatusPart(0, fmt.Sprintf("Hosts: found %d", liveCount))
			// Broadcast-only hosts skip per-host probing; request enrichment.
			if r.Hostname == "" && r.NetBIOS == "" {
				kickNetBIOSProbe(HWND(hwnd), ipStr)
			}
		}

		// Mirror any services to the appropriate broadcast tab.
		for _, svc := range r.Services {
			switch svc.Source {
			case "ssdp":
				listViewAddSSDPRow(hwndListSSDP, ipStr, svc)
				if bcastSSDP == 0 {
					showWindow(hwndSSDPPlaceholder, SW_HIDE)
				}
				bcastSSDP++
			case "wsd":
				listViewAddWSDRow(hwndListWSD, ipStr, svc)
				if bcastWSD == 0 {
					showWindow(hwndWSDPlaceholder, SW_HIDE)
				}
				bcastWSD++
			default:
				listViewAddMDNSRow(hwndListMDNS, ipStr, svc)
				if bcastMDNS == 0 {
					showWindow(hwndMDNSPlaceholder, SW_HIDE)
				}
				bcastMDNS++
			}
		}
		return 0

	case WM_SCAN_COMPLETE:
		scanMu.Lock()
		scanCancel = nil
		scanMu.Unlock()
		scanDuration := time.Since(scanStartTime)
		scanEverCompleted = true
		isScanning = false
		setWindowText(hwndScan, "Scan")
		setStatusPart(0, fmt.Sprintf("Hosts: %d found", liveCount))
		setStatusPart(2, fmt.Sprintf("Scan complete in %.1fs", scanDuration.Seconds()))
		if !listHasHosts {
			setWindowText(hwndListPlaceholder, "No hosts found — try widening the target range")
			showWindow(hwndListPlaceholder, SW_SHOW)
		}
		// Refresh health tab text.
		pendingMu.Lock()
		stats := lastStats
		pendingMu.Unlock()
		updateHealthTab(stats, scanDuration)
		startARPPoll(HWND(hwnd))
		return 0

	case WM_HOST_ENRICH:
		pendingEnrichMu.Lock()
		var e enrichEvent
		if int(wParam) < len(pendingEnriches) {
			e = pendingEnriches[int(wParam)]
		}
		pendingEnrichMu.Unlock()
		if e.ip == "" {
			return 0
		}
		row, ok := ipRowMap[e.ip]
		if !ok {
			return 0
		}
		// Also update the registry.
		en := ensureHostEntry(e.ip)
		en.LastSeen = time.Now()
		if e.netbios != "" {
			cur := listViewGetCellText(hwndList, row, colHost)
			if cur == "\u2014" || cur == "" {
				setSubItem(hwndList, row, colHost, e.netbios+" (NetBIOS)")
				if r, ok2 := rowResultMap[row]; ok2 {
					r.NetBIOS = e.netbios
					rowResultMap[row] = r
				}
			}
			if en.Result.NetBIOS == "" {
				en.Result.NetBIOS = e.netbios
			}
		}
		if e.mac != nil {
			cur := listViewGetCellText(hwndList, row, colMAC)
			if cur == "\u2014" || cur == "" {
				setSubItem(hwndList, row, colMAC, e.mac.String())
				if vendor := sweep.LookupVendor(e.mac); vendor != "" {
					if vc := listViewGetCellText(hwndList, row, colVendor); vc == "\u2014" || vc == "" {
						setSubItem(hwndList, row, colVendor, vendor)
					}
				}
				if r, ok2 := rowResultMap[row]; ok2 {
					r.MAC = e.mac
					if r.Vendor == "" {
						r.Vendor = sweep.LookupVendor(e.mac)
					}
					rowResultMap[row] = r
				}
			}
			if en.Result.MAC == nil {
				en.Result.MAC = e.mac
				if en.Result.Vendor == "" {
					en.Result.Vendor = sweep.LookupVendor(e.mac)
				}
			}
		}
		return 0

	case WM_DESTROY:
		stopScan()
		stopService()
		stopBroadcastListener()
		stopARPPoll()
		postQuitMessage(0)
		return 0
	}
	return defWindowProc(HWND(hwnd), uint32(msg), wParam, lParam)
})

// ---------------------------------------------------------------------------
// Control creation
// ---------------------------------------------------------------------------

func createControls(hwnd HWND) {
	inst := getModuleHandle()
	elevated := isElevated()

	// Fetch the actual DPI for this window now that the HWND exists.
	// This handles the case where the app starts on a non-96-DPI monitor.
	if dpi := getDpiForWindow(hwnd); dpi > 0 {
		currentDPI = dpi
	}

	// ---- elevation status bar (top strip) ----
	// Label spans from the left margin up to the service button; the button
	// sits to the right. They don't overlap, so no z-order paint conflict.
	hwndElevLabel, _ = createWindowEx(0, "STATIC", "Service: starting…",
		WS_CHILD|WS_VISIBLE|SS_LEFT|SS_CENTERIMAGE,
		scale(8), 0, scale(740), scale(elevBarH), hwnd, IDC_ELEV_LABEL, inst)
	// "Elevate sweep service" button — disabled once service reports it is elevated.
	hwndServiceBtn, _ = createWindowEx(0, "BUTTON", "Elevate sweep service",
		WS_CHILD|WS_VISIBLE|WS_TABSTOP,
		scale(756), scale(3), scale(200), scale(26), hwnd, IDC_SERVICE_BTN, inst)
	if elevated {
		enableWindow(hwndServiceBtn, false)
	}
	// Brushes for the elevation status strip (long-lived; also freed on exit).
	brushElevGrey  = createSolidBrush(0x00EBEBEB) // light grey
	brushElevAmber = createSolidBrush(0x00CDF3FF) // light blue/amber
	brushElevGreen = createSolidBrush(0x00DAEDD4) // light green

	// ---- tab control ----
	hwndTabCtrl, _ = createWindowEx(0, WC_TABCONTROL, "",
		WS_CHILD|WS_VISIBLE|WS_TABSTOP|TCS_FLATBUTTONS,
		0, scale(elevBarH), scale(1160), scale(tabCtrlH), hwnd, IDC_TABS, inst)
	insertTab(hwndTabCtrl, 0, "Scanner")
	insertTab(hwndTabCtrl, 1, "mDNS")
	insertTab(hwndTabCtrl, 2, "SSDP")
	insertTab(hwndTabCtrl, 3, "WSD")
	insertTab(hwndTabCtrl, 4, "DHCP")
	insertTab(hwndTabCtrl, 5, "Network")
	insertTab(hwndTabCtrl, 6, "Scan Report")

	// Scan bar sits below the tab strip; only visible when Hosts tab is active.
	scanBarY := scale(elevBarH + tabCtrlH)
	// [Target label] [target input ────────────────────────] [⟲] [Scan/Stop]
	createCtrl("STATIC", "Target:", WS_CHILD|WS_VISIBLE, scale(8), scanBarY+scale(8), scale(48), scale(20), hwnd, 0, inst)
	hwndTarget, _ = createWindowEx(WS_EX_CLIENTEDGE, "EDIT", initialTarget,
		WS_CHILD|WS_VISIBLE|ES_AUTOHSCROLL|WS_TABSTOP,
		scale(58), scanBarY+scale(6), scale(700), scale(22), hwnd, IDC_TARGET, inst)
	hwndDetect, _ = createWindowEx(0, "BUTTON", "⟲",
		WS_CHILD|WS_VISIBLE|WS_TABSTOP, scale(766), scanBarY+scale(5), scale(34), scale(24), hwnd, IDC_DETECT, inst)
	hwndScan, _ = createWindowEx(0, "BUTTON", "Scan",
		WS_CHILD|WS_VISIBLE|WS_TABSTOP, scale(808), scanBarY+scale(5), scale(100), scale(24), hwnd, IDC_SCAN, inst)

	// Hosts listview starts below the scan bar.
	hostsTop := scale(elevBarH + tabCtrlH + scanBarH)
	// All other panes start just below the tab strip (no scan bar).
	otherTop := scale(elevBarH + tabCtrlH)

	// ---- hosts listview (visible) ----
	hwndList, _ = createWindowEx(0, WC_LISTVIEW, "",
		WS_CHILD|WS_VISIBLE|WS_VSCROLL|LVS_REPORT|LVS_SHOWSELALWAYS,
		0, hostsTop, 1160, 600, hwnd, IDC_LIST, inst)
	sendMessage(hwndList, LVM_SETEXTENDEDLISTVIEWSTYLE, 0,
		LVS_EX_FULLROWSELECT|LVS_EX_DOUBLEBUFFER|LVS_EX_HEADERDRAGDROP|LVS_EX_MARQUEESELECT)
	headerHwnd = HWND(sendMessage(hwndList, LVM_GETHEADER, 0, 0))
	// Columns come from hostsColTitles + colDefaultLogicalWidths (single source of truth).
	for i, title := range hostsColTitles {
		if i == int(colLatency) || i == int(colPorts) {
			listViewAddColumnFmt(hwndList, int32(i), title, scale(colDefaultLogicalWidths[i]), LVCFMT_RIGHT)
		} else {
			listViewAddColumn(hwndList, int32(i), title, scale(colDefaultLogicalWidths[i]))
		}
	}
	headerInfos[headerHwnd] = &lvHeaderInfo{hwndList, hostsColTitles[:], colVisible[:], colDefaultLogicalWidths[:]}

	// ---- empty-state placeholder (sits on top of hwndList when no hosts) ----
	hwndListPlaceholder, _ = createWindowEx(0, "STATIC",
		"Enter a target above and click Scan",
		WS_CHILD|WS_VISIBLE|SS_CENTER,
		0, hostsTop+200, 1160, scale(20), hwnd, 0, inst)

	// ---- mDNS listview (hidden initially) ----
	hwndListMDNS, _ = createWindowEx(0, WC_LISTVIEW, "",
		WS_CHILD|WS_VSCROLL|LVS_REPORT|LVS_SHOWSELALWAYS,
		0, otherTop, 1160, 600, hwnd, IDC_LIST_MDNS, inst)
	sendMessage(hwndListMDNS, LVM_SETEXTENDEDLISTVIEWSTYLE, 0,
		LVS_EX_FULLROWSELECT|LVS_EX_DOUBLEBUFFER|LVS_EX_HEADERDRAGDROP|LVS_EX_MARQUEESELECT)
	for i, title := range mdnsColTitles {
		listViewAddColumn(hwndListMDNS, int32(i), title, scale(mdnsDefWidths[i]))
	}
	headerInfos[HWND(sendMessage(hwndListMDNS, LVM_GETHEADER, 0, 0))] =
		&lvHeaderInfo{hwndListMDNS, mdnsColTitles, mdnsColVis, mdnsDefWidths}
	hwndMDNSPlaceholder, _ = createWindowEx(0, "STATIC",
		"Listening — no mDNS traffic detected yet",
		WS_CHILD|SS_CENTER,
		0, otherTop+200, 1160, scale(20), hwnd, 0, inst)

	// ---- SSDP listview (hidden initially) ----
	hwndListSSDP, _ = createWindowEx(0, WC_LISTVIEW, "",
		WS_CHILD|WS_VSCROLL|LVS_REPORT|LVS_SHOWSELALWAYS,
		0, otherTop, 1160, 600, hwnd, IDC_LIST_SSDP, inst)
	sendMessage(hwndListSSDP, LVM_SETEXTENDEDLISTVIEWSTYLE, 0,
		LVS_EX_FULLROWSELECT|LVS_EX_DOUBLEBUFFER|LVS_EX_HEADERDRAGDROP|LVS_EX_MARQUEESELECT)
	for i, title := range ssdpColTitles {
		listViewAddColumn(hwndListSSDP, int32(i), title, scale(ssdpDefWidths[i]))
	}
	headerInfos[HWND(sendMessage(hwndListSSDP, LVM_GETHEADER, 0, 0))] =
		&lvHeaderInfo{hwndListSSDP, ssdpColTitles, ssdpColVis, ssdpDefWidths}
	hwndSSDPPlaceholder, _ = createWindowEx(0, "STATIC",
		"Listening — no SSDP traffic detected yet",
		WS_CHILD|SS_CENTER,
		0, otherTop+200, 1160, scale(20), hwnd, 0, inst)

	// ---- WS-Discovery listview (hidden initially) ----
	hwndListWSD, _ = createWindowEx(0, WC_LISTVIEW, "",
		WS_CHILD|WS_VSCROLL|LVS_REPORT|LVS_SHOWSELALWAYS,
		0, otherTop, 1160, 600, hwnd, IDC_LIST_WSD, inst)
	sendMessage(hwndListWSD, LVM_SETEXTENDEDLISTVIEWSTYLE, 0,
		LVS_EX_FULLROWSELECT|LVS_EX_DOUBLEBUFFER|LVS_EX_HEADERDRAGDROP|LVS_EX_MARQUEESELECT)
	for i, title := range wsdColTitles {
		listViewAddColumn(hwndListWSD, int32(i), title, scale(wsdDefWidths[i]))
	}
	headerInfos[HWND(sendMessage(hwndListWSD, LVM_GETHEADER, 0, 0))] =
		&lvHeaderInfo{hwndListWSD, wsdColTitles, wsdColVis, wsdDefWidths}
	hwndWSDPlaceholder, _ = createWindowEx(0, "STATIC",
		"Listening — no WS-Discovery traffic detected yet",
		WS_CHILD|SS_CENTER,
		0, otherTop+200, 1160, scale(20), hwnd, 0, inst)

	// ---- DHCP listview (hidden initially) ----
	hwndListDHCP, _ = createWindowEx(0, WC_LISTVIEW, "",
		WS_CHILD|WS_VSCROLL|LVS_REPORT|LVS_SHOWSELALWAYS,
		0, otherTop, 1160, 600, hwnd, IDC_LIST_DHCP, inst)
	sendMessage(hwndListDHCP, LVM_SETEXTENDEDLISTVIEWSTYLE, 0,
		LVS_EX_FULLROWSELECT|LVS_EX_DOUBLEBUFFER|LVS_EX_HEADERDRAGDROP|LVS_EX_MARQUEESELECT)
	for i, title := range dhcpColTitles {
		listViewAddColumn(hwndListDHCP, int32(i), title, scale(dhcpDefWidths[i]))
	}
	headerInfos[HWND(sendMessage(hwndListDHCP, LVM_GETHEADER, 0, 0))] =
		&lvHeaderInfo{hwndListDHCP, dhcpColTitles, dhcpColVis, dhcpDefWidths}
	hwndDHCPPlaceholder, _ = createWindowEx(0, "STATIC",
		"Listening — no DHCP traffic detected yet (requires elevation)",
		WS_CHILD|SS_CENTER,
		0, otherTop+200, 1160, scale(20), hwnd, 0, inst)

	// ---- network text area (hidden initially) ----
	hwndListNetwork, _ = createWindowEx(
		WS_EX_CLIENTEDGE, "EDIT", "Waiting for broadcast traffic…",
		WS_CHILD|WS_VSCROLL|ES_MULTILINE|ES_READONLY|ES_AUTOVSCROLL,
		0, otherTop, 1160, 600, hwnd, IDC_LIST_NETWORK, inst)

	// ---- scan report text area (hidden initially) ----
	hwndListHealth, _ = createWindowEx(
		WS_EX_CLIENTEDGE, "EDIT", "",
		WS_CHILD|WS_VSCROLL|ES_MULTILINE|ES_READONLY|ES_AUTOVSCROLL,
		0, otherTop, 1160, 600, hwnd, 0, inst)
	hwndHealthPlaceholder, _ = createWindowEx(0, "STATIC",
		"Run a scan to populate this report",
		WS_CHILD|SS_CENTER,
		0, otherTop+200, 1160, scale(20), hwnd, 0, inst)

	// ---- status bar — 3 parts: Hosts | Broadcast | Scan state ----
	hwndStatus = createStatusWindow(hwnd, IDC_STATUS, "")
	// Parts: first two fixed-width, last part fills the remainder (-1).
	// We set widths after the window is shown (resizeControls will re-set them),
	// but initialise now so text is visible immediately.
	setStatusParts(400, 650)
	setStatusPart(0, "Ready")
	setStatusPart(1, "Broadcast: listening…")
	setStatusPart(2, "Enter a target and click Scan")

	// Apply Segoe UI to every child control (labels, buttons, edits, listviews, tabs).
	// Use the actual window DPI (set above) so the font is correct on all monitors.
	appFont = createUIFont(currentDPI)
	setFontAllChildren(hwnd, appFont)

	// Apply Consolas to the two text-report panes so aligned columns line up.
	monoFont := createMonoFont()
	sendMessage(hwndListNetwork, WM_SETFONT, uintptr(monoFont), 1)
	sendMessage(hwndListHealth, WM_SETFONT, uintptr(monoFont), 1)
}

// createCtrl is a shorthand for plain child controls (STATIC, BUTTON).
func createCtrl(class, title string, style uint32, x, y, w, h int32, parent HWND, id uintptr, inst HINSTANCE) HWND {
	hwnd, _ := createWindowEx(0, class, title, style, x, y, w, h, parent, HMENU(id), inst)
	return hwnd
}

// ---------------------------------------------------------------------------
// Layout — resize all panes to fill the client area
// ---------------------------------------------------------------------------

func resizeControls(hwnd HWND, lParam uintptr) {
	width := loword(lParam)
	height := hiword(lParam)

	// Status bar resizes itself; then recompute part boundaries.
	sendMessage(hwndStatus, WM_SIZE, 0, lParam)
	statusR := getClientRect(hwndStatus)
	statusH := statusR.Bottom - statusR.Top
	p1 := width / 3
	p2 := p1 * 2
	setStatusParts(p1, p2)

	// Elevation bar: label stretches up to the service button.
	moveWindow(hwndElevLabel, scale(8), 0, width-scale(220), scale(elevBarH))
	moveWindow(hwndServiceBtn, width-scale(212), scale(3), scale(204), scale(26))
	moveWindow(hwndTabCtrl, 0, scale(elevBarH), width, scale(tabCtrlH))

	// Scan bar: target stretches, detect + scan/stop buttons anchor to right.
	scanBarY := scale(elevBarH + tabCtrlH)
	moveWindow(hwndTarget, scale(58), scanBarY+scale(6), width-scale(228), scale(22))
	moveWindow(hwndDetect, width-scale(162), scanBarY+scale(5), scale(34), scale(24))
	moveWindow(hwndScan, width-scale(120), scanBarY+scale(5), scale(100), scale(24))

	// Hosts tab: list sits below the scan bar.
	hostsTop := scale(elevBarH + tabCtrlH + scanBarH)
	hostsH := height - hostsTop - statusH
	if hostsH < 0 {
		hostsH = 0
	}
	moveWindow(hwndList, 0, hostsTop, width, hostsH)
	// Placeholder centered vertically within the list area.
	moveWindow(hwndListPlaceholder, 0, hostsTop+(hostsH-scale(20))/2, width, scale(20))

	// All other panes fill from just below the tab strip.
	otherTop := scale(elevBarH + tabCtrlH)
	otherH := height - otherTop - statusH
	if otherH < 0 {
		otherH = 0
	}
	moveWindow(hwndListMDNS, 0, otherTop, width, otherH)
	moveWindow(hwndMDNSPlaceholder, 0, otherTop+(otherH-scale(20))/2, width, scale(20))
	moveWindow(hwndListSSDP, 0, otherTop, width, otherH)
	moveWindow(hwndSSDPPlaceholder, 0, otherTop+(otherH-scale(20))/2, width, scale(20))
	moveWindow(hwndListWSD, 0, otherTop, width, otherH)
	moveWindow(hwndWSDPlaceholder, 0, otherTop+(otherH-scale(20))/2, width, scale(20))
	moveWindow(hwndListDHCP, 0, otherTop, width, otherH)
	moveWindow(hwndDHCPPlaceholder, 0, otherTop+(otherH-scale(20))/2, width, scale(20))
	moveWindow(hwndListNetwork, 0, otherTop, width, otherH)
	moveWindow(hwndListHealth, 0, otherTop, width, otherH)
	moveWindow(hwndHealthPlaceholder, 0, otherTop+(otherH-scale(20))/2, width, scale(20))
}

// ---------------------------------------------------------------------------
// Scan start / stop
// ---------------------------------------------------------------------------

func startScan(hwnd HWND) {
	scanMu.Lock()
	if scanCancel != nil {
		scanMu.Unlock()
		return // already running
	}
	scanMu.Unlock()

	target := getWindowText(hwndTarget)
	if target == "" {
		messageBox(hwnd, "Enter a target IP or CIDR.", "net-sweep", 0)
		return
	}

	// WAN safety: warn if the target is not an RFC1918 / private range.
	if !sweep.IsPrivate(target) {
		r := messageBox(hwnd,
			"Target \""+target+"\" is not a private/RFC1918 address.\n\n"+
				"Scanning hosts you do not own may violate laws or terms of service.\n\n"+
				"Proceed anyway?",
			"WAN Target Warning",
			MB_YESNO|MB_ICONWARNING)
		if r != IDYES {
			return
		}
	}

	appCfg, _, _ := config.Load()
	scanCfg := appCfg.ToSweepConfig()
	// Disable per-scan mDNS/SSDP; background listener handles those continuously.
	scanCfg.BroadcastListen = 0

	// Expand target first so we can pre-populate the list.
	hosts, err := sweep.ExpandTarget(target)
	if err != nil {
		messageBox(hwnd, "Invalid target: "+err.Error(), "net-sweep", 0)
		return
	}

	scanMu.Lock()
	if scanCancel != nil { // re-check after the dialogs above
		scanMu.Unlock()
		return
	}
	_, cancel := context.WithCancel(context.Background())
	scanCancel = cancel
	scanMu.Unlock()

	// Reset display state.
	liveCount = 0
	sortCol = -1
	sortAsc = true
	updateSortIndicators()
	pendingMu.Lock()
	pendingResults = pendingResults[:0]
	pendingMu.Unlock()

	sendMessage(hwndList, LVM_DELETEALLITEMS, 0, 0)
	ipRowMap = make(map[string]int32, len(hosts))
	rowResultMap = make(map[int32]sweep.Result, len(hosts))

	// Pre-populate every IP with a "Pending" row so they appear in order.
	for _, ip := range hosts {
		ipStr := ip.String()
		row := listViewInsertPendingRow(hwndList, ipStr)
		ipRowMap[ipStr] = row
	}

	isScanning = true
	listHasHosts = false
	scanStartTime = time.Now()
	setWindowText(hwndScan, "Stop")
	showWindow(hwndListPlaceholder, SW_HIDE)
	setStatusPart(2, statusForService()+" — scanning")

	// Route all scans through the persistent sweep service.
	if serviceRunning() {
		sendScanViaService(hwnd, target, scanCfg)
		return
	}

	// Fallback: service not ready yet; run scan in-process.
	ctx, cancel2 := context.WithCancel(context.Background())
	scanMu.Lock()
	scanCancel = cancel2
	scanMu.Unlock()
	go func() {
		defer func() {
			if p := recover(); p != nil {
				writeCrashLog(hwnd, p)
				postMessage(hwnd, WM_SCAN_COMPLETE, 0, 0)
			}
		}()
		sc := sweep.NewScanner(scanCfg)
		ch, err := sc.Scan(ctx, target)
		if err != nil {
			postMessage(hwnd, WM_SCAN_COMPLETE, 0, 0)
			return
		}
		for r := range ch {
			pendingMu.Lock()
			idx := len(pendingResults)
			pendingResults = append(pendingResults, r)
			pendingMu.Unlock()
			postMessage(hwnd, WM_SCAN_RESULT, uintptr(idx), 0)
		}
		pendingMu.Lock()
		lastStats = sc.Stats
		pendingMu.Unlock()
		postMessage(hwnd, WM_SCAN_COMPLETE, 0, 0)
	}()
}

// detectSubnet fills the target box with the detected local subnet.
// If a single private subnet is found, it is filled silently.
// If multiple are found, a popup menu lets the user pick one.
// Called from the UI thread only.
func detectSubnet(hwnd HWND) {
	subnets := sweep.DetectLocalSubnets()
	switch len(subnets) {
	case 0:
		messageBox(hwnd, "No private IPv4 interface detected.\n\nConnect to a network and try again.",
			"Detect Local Subnet", 0)
	case 1:
		setWindowText(hwndTarget, subnets[0])
	default:
		// Multiple interfaces — offer a popup menu.
		menu := createPopupMenu()
		for i, s := range subnets {
			appendMenu(menu, MF_STRING, uintptr(IDM_DETECT_BASE+i), s)
		}
		pt := getClientPtBelowControl(hwndDetect)
		cmd := trackPopupMenu(menu, TPM_LEFTALIGN|TPM_TOPALIGN|TPM_RETURNCMD, pt.X, pt.Y, hwnd)
		destroyMenu(menu)
		if cmd >= IDM_DETECT_BASE && int(cmd-IDM_DETECT_BASE) < len(subnets) {
			setWindowText(hwndTarget, subnets[cmd-IDM_DETECT_BASE])
		}
	}
}

// getClientPtBelowControl returns the screen position just below a control,
// suitable for placing a popup menu flush with the button.
func getClientPtBelowControl(ctrl HWND) POINT {
	r := getWindowRect(ctrl)
	return POINT{X: r.Left, Y: r.Bottom}
}

func stopScan() {
	stopServiceScan() // send stop command to service if running
	scanMu.Lock()
	defer scanMu.Unlock()
	if scanCancel != nil {
		scanCancel()
		scanCancel = nil
	}
}

// exportResults saves the current results to a JSON or CSV file via a Save dialog.
func exportResults(hwnd HWND, format string) {
	pendingMu.Lock()
	results := make([]sweep.Result, 0, len(pendingResults))
	for _, r := range pendingResults {
		if r.Alive {
			results = append(results, r)
		}
	}
	pendingMu.Unlock()

	if len(results) == 0 {
		messageBox(hwnd, "No results to export. Run a scan first.", "Export", 0)
		return
	}

	var title, defExt, filter, path string
	if format == "json" {
		title = "Export as JSON"
		defExt = "json"
		filter = "JSON files|*.json|All files|*.*|"
	} else {
		title = "Export as CSV"
		defExt = "csv"
		filter = "CSV files|*.csv|All files|*.*|"
	}

	path = getSaveFileName(hwnd, title, defExt, filter)
	if path == "" {
		return // user cancelled
	}

	f, err := os.Create(path)
	if err != nil {
		messageBox(hwnd, "Could not create file:\n"+err.Error(), "Export Error", 0)
		return
	}
	defer f.Close()

	if format == "json" {
		err = sweep.WriteJSON(f, results)
	} else {
		err = sweep.WriteCSV(f, results)
	}
	if err != nil {
		messageBox(hwnd, "Export failed:\n"+err.Error(), "Export Error", 0)
		return
	}
	messageBox(hwnd, "Exported "+fmt.Sprintf("%d", len(results))+" hosts to:\n"+path, "Export Complete", 0)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// setStatusParts sets the right-edge pixel positions for the three status bar
// parts. Pass p1, p2 as the right edge of part 0 and part 1; part 2 fills
// the remainder (represented as -1).
func setStatusParts(p1, p2 int32) {
	parts := [3]int32{p1, p2, -1}
	sendMessage(hwndStatus, SB_SETPARTS, 3, uintptr(unsafe.Pointer(&parts[0])))
}

// setStatusPart sets the text of one status bar part (0=Hosts, 1=Broadcast, 2=State).
func setStatusPart(part uintptr, s string) {
	p, _ := syscall.UTF16PtrFromString(s)
	sendMessage(hwndStatus, SB_SETTEXT, part, uintptr(unsafe.Pointer(p)))
}

// setStatus is a convenience wrapper that updates the rightmost (state) part.
func setStatus(s string) { setStatusPart(2, s) }

// updateNetworkTab refreshes the Network tab with live broadcast stats.
// Called on the UI thread whenever a broadcast entry arrives or service state changes.
func updateNetworkTab() {
	text := fmt.Sprintf(
		"NetScope — Live Network Activity\r\n"+
			"══════════════════════════════════════════\r\n\r\n"+
			"  Sweep service          : %s\r\n\r\n"+
			"  Broadcast listeners    : mDNS + SSDP (running since app start)\r\n"+
			"  mDNS services seen     : %d\r\n"+
			"  SSDP devices seen      : %d\r\n"+
			"  Total broadcast events : %d\r\n\r\n"+
			"══════════════════════════════════════════\r\n"+
			"Notes:\r\n"+
			"  • mDNS and SSDP rows are listed in detail on their respective tabs.\r\n"+
			"  • Counts accumulate continuously; they are not reset between scans.\r\n"+
			"  • Elevating the service enables ARP + ICMP for richer scan results.\r\n",
		statusForService(),
		bcastMDNS,
		bcastSSDP,
		bcastCount,
	)
	setWindowText(hwndListNetwork, text)
}

// updateHealthTab fills the Scan Report tab with stats from the last scan.
func updateHealthTab(stats sweep.ScanStats, duration time.Duration) {
	showWindow(hwndHealthPlaceholder, SW_HIDE)
	arpLine := "None detected."
	if stats.ARPAnomalies > 0 {
		arpLine = fmt.Sprintf("%d — same IP seen with different MACs (possible duplicate IP or ARP spoofing). Investigate with 'arp -a'.", stats.ARPAnomalies)
	}

	text := fmt.Sprintf(
		"NetScope — Scan Report\r\n"+
			"══════════════════════════════════════════\r\n\r\n"+
			"  Scan duration           : %.1f s\r\n"+
			"  Hosts found             : %d\r\n"+
			"  Packets sent            : %d\r\n"+
			"  Replies received        : %d\r\n"+
			"  Timeouts                : %d\r\n"+
			"  Average latency         : %.2f ms\r\n\r\n"+
			"  Hosts without PTR       : %d\r\n"+
			"  ARP anomalies           : %s\r\n\r\n"+
			"══════════════════════════════════════════\r\n"+
			"Notes:\r\n"+
			"  • Hosts without PTR: many networks have no reverse DNS. This is\r\n"+
			"    normal and does not indicate a problem with the host.\r\n"+
			"  • ARP anomalies are genuinely unusual and worth investigating.\r\n",
		duration.Seconds(),
		liveCount,
		stats.PacketsSent,
		stats.RepliesReceived,
		stats.Timeouts,
		stats.AvgLatencyMS(),
		stats.DNSFailures,
		arpLine,
	)
	setWindowText(hwndListHealth, text)
}

// ---------------------------------------------------------------------------
// Right-click context menu for a host in the list
// ---------------------------------------------------------------------------

// portOpen returns true if port is in r.OpenPorts.
func portOpen(r sweep.Result, port int) bool {
	for _, p := range r.OpenPorts {
		if p == port {
			return true
		}
	}
	return false
}

// menuItem appends a string item, greyed when !enabled.
func menuItem(menu HMENU, id uintptr, label string, enabled bool) {
	flags := uint32(MF_STRING)
	if !enabled {
		flags |= MF_GRAYED
	}
	appendMenu(menu, flags, id, label)
}

// copyToClipboard places text on the Windows clipboard as CF_UNICODETEXT.
func copyToClipboard(hwnd HWND, text string) {
	utf16, err := syscall.UTF16FromString(text)
	if err != nil {
		return
	}
	// Allocate global memory: len(utf16) * 2 bytes (each uint16 = 2 bytes).
	const GMEM_MOVEABLE = 0x0002
	const CF_UNICODETEXT = 13
	hMem, _, _ := procGlobalAlloc.Call(GMEM_MOVEABLE, uintptr(len(utf16)*2))
	if hMem == 0 {
		return
	}
	ptr, _, _ := procGlobalLock.Call(hMem)
	if ptr == 0 {
		return
	}
	procRtlMoveMemory.Call(ptr, uintptr(unsafe.Pointer(&utf16[0])), uintptr(len(utf16)*2))
	procGlobalUnlock.Call(hMem)

	procOpenClipboard.Call(uintptr(hwnd))
	procEmptyClipboard.Call()
	procSetClipboardData.Call(CF_UNICODETEXT, hMem)
	procCloseClipboard.Call()
}

// showHostContextMenu builds and tracks a context menu for the given Result at
// screen coordinates (x, y).
// listViewInfoFor returns the HWND, column count, and canonical header strings
// for the list-view identified by its control ID. Returns zero HWND if unknown.
func listViewInfoFor(idFrom uintptr) (hw HWND, numCols int32, headers []string) {
	switch idFrom {
	case IDC_LIST:
		return hwndList, int32(len(hostsColTitles)), hostsColTitles[:]
	case IDC_LIST_MDNS:
		return hwndListMDNS, int32(len(mdnsColTitles)), mdnsColTitles
	case IDC_LIST_SSDP:
		return hwndListSSDP, int32(len(ssdpColTitles)), ssdpColTitles
	case IDC_LIST_WSD:
		return hwndListWSD, int32(len(wsdColTitles)), wsdColTitles
	case IDC_LIST_DHCP:
		return hwndListDHCP, int32(len(dhcpColTitles)), dhcpColTitles
	}
	return 0, 0, nil
}

func showHostContextMenu(parent HWND, r sweep.Result, x, y int32) {
	ip := r.IP.String()

	menu := createPopupMenu()
	defer destroyMenu(menu)

	// ── Connect submenu ──────────────────────────────────────────────────────
	hConn := createPopupMenu()
	menuItem(hConn, IDM_CTX_OPEN_HTTP,   "HTTP (port 80)",   portOpen(r, 80))
	menuItem(hConn, IDM_CTX_OPEN_HTTPS,  "HTTPS (port 443)", portOpen(r, 443))
	appendMenu(hConn, MF_SEPARATOR, 0, "")
	menuItem(hConn, IDM_CTX_OPEN_SSH,    "SSH (port 22)",    portOpen(r, 22))
	menuItem(hConn, IDM_CTX_OPEN_RDP,    "RDP (port 3389)",  portOpen(r, 3389))
	appendMenu(hConn, MF_SEPARATOR, 0, "")
	menuItem(hConn, IDM_CTX_OPEN_FTP,    "FTP (port 21)",    portOpen(r, 21))
	menuItem(hConn, IDM_CTX_OPEN_TELNET, "Telnet (port 23)", portOpen(r, 23))
	menuItem(hConn, IDM_CTX_OPEN_SMB,    "File Share / SMB (port 445)", portOpen(r, 445))

	appendMenu(menu, MF_POPUP, uintptr(hConn), "Connect")
	appendMenu(menu, MF_SEPARATOR, 0, "")

	// ── Ping ─────────────────────────────────────────────────────────────────
	menuItem(menu, IDM_CTX_PING,      "Ping once",     true)
	menuItem(menu, IDM_CTX_PING_CONT, "Ping -t (continuous)", true)
	appendMenu(menu, MF_SEPARATOR, 0, "")

	// ── Copy ─────────────────────────────────────────────────────────────────
	menuItem(menu, IDM_CTX_COPY_IP, "Copy IP", r.IP != nil)
	appendCopyAsSubmenu(menu) // copies all selected rows in chosen format
	appendMenu(menu, MF_SEPARATOR, 0, "")
	menuItem(menu, IDM_CTX_VIEW_DETAILS, "View details\u2026", true)

	cmd := trackPopupMenu(menu, TPM_LEFTALIGN|TPM_TOPALIGN|TPM_RETURNCMD, x, y, parent)
	rows := listViewGetSelectedRows(hwndList)
	if handleCopyAsCmd(parent, hwndList, cmd, rows, 10, hostsColTitles[:]) {
		return
	}
	switch cmd {
	case IDM_CTX_OPEN_HTTP:
		shellExecute(parent, "open", "http://"+ip, "", "", SW_SHOW)
	case IDM_CTX_OPEN_HTTPS:
		shellExecute(parent, "open", "https://"+ip, "", "", SW_SHOW)
	case IDM_CTX_OPEN_SSH:
		shellExecute(parent, "open", "ssh://"+ip, "", "", SW_SHOW)
	case IDM_CTX_OPEN_RDP:
		shellExecute(parent, "open", "mstsc.exe", "/v:"+ip, "", SW_SHOW)
	case IDM_CTX_OPEN_FTP:
		shellExecute(parent, "open", "ftp://"+ip, "", "", SW_SHOW)
	case IDM_CTX_OPEN_TELNET:
		shellExecute(parent, "open", "telnet://"+ip, "", "", SW_SHOW)
	case IDM_CTX_OPEN_SMB:
		shellExecute(parent, "open", `\\`+ip, "", "", SW_SHOW)
	case IDM_CTX_PING:
		shellExecute(parent, "open", "cmd.exe",
			"/c ping "+ip+" && pause", "", SW_SHOW)
	case IDM_CTX_PING_CONT:
		shellExecute(parent, "open", "cmd.exe",
			"/k ping -t "+ip, "", SW_SHOW)
	case IDM_CTX_COPY_IP:
		copyToClipboard(parent, ip)
	case IDM_CTX_VIEW_DETAILS:
		showHostDetailDialog(parent, ip)
	}
}

