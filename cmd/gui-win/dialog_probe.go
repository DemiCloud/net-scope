//go:build windows

package guiwin

import (
	"fmt"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/demicloud/net-scope/internal/scan"
)

// ---------------------------------------------------------------------------
// Pending deep probe event queue  (receive goroutine → UI thread)
// ---------------------------------------------------------------------------

var (
	pendingProbeEvents   []scan.ProbeEvent
	pendingProbeEventsMu sync.Mutex
)

// ---------------------------------------------------------------------------
// Probe dialog control IDs
// ---------------------------------------------------------------------------

const (
	idProbeIP        = 2001
	idProbePort      = 2002
	idProbeTransport = 2003 // static label: "TCP" or "UDP"
	idProbeSelect    = 2004 // "Select Probe ▸" button
	idProbeRun       = 2005 // "Run" / "Stop" button
	idProbeOutput    = 2006 // multiline read-only Edit
	idProbeCopy      = 2007 // "Copy Output" button
	idProbeClose     = 2008 // "Close" button

	idProbeTimerID uintptr = 55 // WM_TIMER nIDEvent

	// probeMenuBase is the first WM_COMMAND ID used by probe selection entries
	// in the TrackPopupMenu. Range: probeMenuBase … probeMenuBase+len(allProbes)-1.
	probeMenuBase = 5000
)

// ---------------------------------------------------------------------------
// Probe dialog state  (UI thread only, except hwndProbeDlgAtomic)
// ---------------------------------------------------------------------------

var (
	hwndProbeIP        HWND
	hwndProbePort      HWND
	hwndProbeTransport HWND
	hwndProbeSelect    HWND
	hwndProbeRun       HWND
	hwndProbeOutput    HWND

	probeDlgIPLocked      bool
	probeDlgSelectedProbe *scan.DeepProbe
	probeDlgRunID         string
	probeDlgRunning       bool
	probeDlgLastOutputAt  time.Time

	// Snapshot of the probe catalog taken when the dialog opens so that menu
	// item indices remain stable for the dialog's lifetime.
	probeDlgAllProbes []scan.DeepProbe
)

// ---------------------------------------------------------------------------
// Window procedure
// ---------------------------------------------------------------------------

var probeDlgWndProc = syscall.NewCallback(func(hwnd, msg, wParam, lParam uintptr) uintptr {
	switch uint32(msg) {
	case WM_CREATE:
		createProbeDialogControls(HWND(hwnd))
		setTimer(HWND(hwnd), idProbeTimerID, 1000, 0)
		return 0

	case WM_CTLCOLORSTATIC:
		return ctlColorDialog(wParam)

	case WM_COMMAND:
		switch loword(wParam) {
		case idProbeSelect:
			probeDlgShowProbeMenu(HWND(hwnd))
		case idProbeRun:
			if probeDlgRunning {
				probeDlgStop()
			} else {
				probeDlgStart(HWND(hwnd))
			}
		case idProbeCopy:
			probeDlgCopyOutput()
		case idProbeClose:
			killTimer(HWND(hwnd), idProbeTimerID)
			if probeDlgRunning {
				probeDlgStop()
			}
			atomic.StoreUintptr(&hwndProbeDlgAtomic, 0)
			closeModal(HWND(hwnd))
		}
		return 0

	case WM_PROBE_EVENT:
		pendingProbeEventsMu.Lock()
		var evt scan.ProbeEvent
		if int(wParam) < len(pendingProbeEvents) {
			evt = pendingProbeEvents[int(wParam)]
		}
		pendingProbeEventsMu.Unlock()
		if evt.RunID != probeDlgRunID {
			return 0 // stale event from a superseded run
		}
		if evt.Text != "" {
			probeDlgAppendLine(evt.Text)
			probeDlgLastOutputAt = time.Now()
		}
		return 0

	case WM_PROBE_DONE:
		pendingProbeEventsMu.Lock()
		var evt scan.ProbeEvent
		if int(wParam) < len(pendingProbeEvents) {
			evt = pendingProbeEvents[int(wParam)]
		}
		pendingProbeEventsMu.Unlock()
		if evt.RunID != probeDlgRunID {
			return 0 // stale
		}
		probeDlgRunning = false
		setWindowText(hwndProbeRun, "Run")
		enableWindow(hwndProbeSelect, true)
		if evt.Err != "" {
			probeDlgAppendLine("Error: " + evt.Err)
		}
		probeDlgAppendLine("——— done ———")
		return 0

	case WM_TIMER:
		if uintptr(wParam) == idProbeTimerID && probeDlgRunning {
			if time.Since(probeDlgLastOutputAt) >= 1*time.Second {
				probeDlgAppendDot()
				probeDlgLastOutputAt = time.Now()
			}
		}
		return 0

	case WM_CLOSE:
		killTimer(HWND(hwnd), idProbeTimerID)
		if probeDlgRunning {
			probeDlgStop()
		}
		atomic.StoreUintptr(&hwndProbeDlgAtomic, 0)
		closeModal(HWND(hwnd))
		return 0
	}
	return defWindowProc(HWND(hwnd), uint32(msg), wParam, lParam)
})

// ---------------------------------------------------------------------------
// Control creation
// ---------------------------------------------------------------------------

func createProbeDialogControls(hwnd HWND) {
	inst := getModuleHandle()

	// Row 1: IP address ─ Port ─ Transport label.
	createCtrl("STATIC", "IP:", WS_CHILD|WS_VISIBLE, 10, 14, 18, 16, hwnd, 0, inst)
	hwndProbeIP = createCtrl("EDIT", "",
		WS_CHILD|WS_VISIBLE|WS_BORDER|ES_AUTOHSCROLL,
		32, 11, 130, 20, hwnd, idProbeIP, inst)
	if probeDlgIPLocked {
		sendMessage(hwndProbeIP, EM_SETREADONLY, 1, 0)
	}
	createCtrl("STATIC", "Port:", WS_CHILD|WS_VISIBLE, 170, 14, 30, 16, hwnd, 0, inst)
	hwndProbePort = createCtrl("EDIT", "",
		WS_CHILD|WS_VISIBLE|WS_BORDER|ES_AUTOHSCROLL|ES_NUMBER,
		204, 11, 55, 20, hwnd, idProbePort, inst)
	hwndProbeTransport = createCtrl("STATIC", "TCP",
		WS_CHILD|WS_VISIBLE, 265, 14, 28, 16, hwnd, idProbeTransport, inst)

	// Row 1 (right side): probe selector + Run button.
	hwndProbeSelect = createCtrl("BUTTON", "Select Probe \u25be",
		WS_CHILD|WS_VISIBLE|WS_TABSTOP, 302, 10, 150, 22, hwnd, idProbeSelect, inst)
	hwndProbeRun = createCtrl("BUTTON", "Run",
		WS_CHILD|WS_VISIBLE|WS_TABSTOP, 460, 10, 50, 22, hwnd, idProbeRun, inst)

	// Output area label + multiline read-only Edit.
	createCtrl("STATIC", "Output:", WS_CHILD|WS_VISIBLE, 10, 40, 60, 16, hwnd, 0, inst)
	hwndProbeOutput = createCtrl("EDIT", "",
		WS_CHILD|WS_VISIBLE|WS_BORDER|WS_VSCROLL|
			ES_MULTILINE|ES_AUTOVSCROLL|ES_READONLY,
		10, 58, 494, 294, hwnd, idProbeOutput, inst)

	// Bottom row: Copy + Close.
	createCtrl("BUTTON", "Copy Output",
		WS_CHILD|WS_VISIBLE|WS_TABSTOP, 10, 362, 100, 24, hwnd, idProbeCopy, inst)
	createCtrl("BUTTON", "Close",
		WS_CHILD|WS_VISIBLE|WS_TABSTOP, 444, 362, 66, 24, hwnd, idProbeClose, inst)
}

// ---------------------------------------------------------------------------
// Probe selection menu
// ---------------------------------------------------------------------------

func probeDlgShowProbeMenu(dlg HWND) {
	probes := probeDlgAllProbes
	if len(probes) == 0 {
		messageBox(dlg, "No probes are registered.\n\n"+
			"Make sure probes.Register() is called at startup.", "Probe", MB_ICONINFORMATION)
		return
	}

	// Build one submenu per group.
	type groupEntry struct {
		name string
		hm   HMENU
	}
	var groups []groupEntry
	groupIdx := make(map[string]int)

	for i, p := range probes {
		gi, ok := groupIdx[p.Group]
		if !ok {
			gi = len(groups)
			groupIdx[p.Group] = gi
			groups = append(groups, groupEntry{name: p.Group, hm: createPopupMenu()})
		}
		appendMenu(groups[gi].hm, MF_STRING, uintptr(probeMenuBase+i), p.Name)
	}

	// Top-level menu with one submenu per group.
	hRoot := createPopupMenu()
	for _, g := range groups {
		appendMenu(hRoot, MF_POPUP, uintptr(g.hm), g.name)
	}

	// Show the menu below the Select button.
	btnRC := getWindowRect(hwndProbeSelect)
	cmdID := int(trackPopupMenu(hRoot, TPM_RETURNCMD|TPM_RIGHTBUTTON,
		btnRC.Left, btnRC.Bottom, dlg))

	// Tear down menus.
	for _, g := range groups {
		destroyMenu(g.hm)
	}
	destroyMenu(hRoot)

	if cmdID < probeMenuBase || cmdID >= probeMenuBase+len(probes) {
		return // dismissed or out of range
	}
	p := &probeDlgAllProbes[cmdID-probeMenuBase]
	probeDlgSelectedProbe = p

	setWindowText(hwndProbeSelect, p.Name)
	setWindowText(hwndProbePort, fmt.Sprintf("%d", p.DefaultPort))
	setWindowText(hwndProbeTransport, p.Transport)
}

// ---------------------------------------------------------------------------
// Run / Stop
// ---------------------------------------------------------------------------

func probeDlgStart(dlg HWND) {
	if probeDlgSelectedProbe == nil {
		messageBox(dlg, "Please select a probe first.", "Probe", MB_ICONINFORMATION)
		return
	}
	ip := getWindowText(hwndProbeIP)
	if ip == "" {
		messageBox(dlg, "Enter an IP address.", "Probe", MB_ICONINFORMATION)
		return
	}
	portStr := getWindowText(hwndProbePort)
	port := 0
	fmt.Sscanf(portStr, "%d", &port) //nolint:errcheck
	if port <= 0 || port > 65535 {
		messageBox(dlg, "Enter a valid port number (1–65535).", "Probe", MB_ICONINFORMATION)
		return
	}

	// Unique run token to correlate streaming events back to this specific run.
	runID := fmt.Sprintf("probe-%d", time.Now().UnixNano())
	probeDlgRunID = runID
	probeDlgRunning = true
	probeDlgLastOutputAt = time.Now()

	// Clear previous output and show a "starting" line.
	setWindowText(hwndProbeOutput, "")
	probeDlgAppendLine(fmt.Sprintf("Running %s on %s:%d…", probeDlgSelectedProbe.Name, ip, port))
	setWindowText(hwndProbeRun, "Stop")
	enableWindow(hwndProbeSelect, false)

	// Send the probe command to the sensor service.
	serviceMu.Lock()
	enc := serviceEnc
	serviceMu.Unlock()
	if enc == nil {
		probeDlgAppendLine("⚠  Scan service is not running. Start the service first.")
		probeDlgRunning = false
		setWindowText(hwndProbeRun, "Run")
		enableWindow(hwndProbeSelect, true)
		return
	}
	cmd := scan.ServiceCmd{
		Cmd:    "probe",
		Target: ip,
		Probe: &scan.ProbeSpec{
			Port:       port,
			ExtProbeID: probeDlgSelectedProbe.ID,
			RunID:      runID,
		},
	}
	serviceEncMu.Lock()
	err := enc.Encode(cmd)
	serviceEncMu.Unlock()
	if err != nil {
		probeDlgAppendLine("⚠  Failed to send probe command: " + err.Error())
		probeDlgRunning = false
		setWindowText(hwndProbeRun, "Run")
		enableWindow(hwndProbeSelect, true)
	}
}

func probeDlgStop() {
	// Mark as stopped. The service goroutine will finish and send a Done event,
	// which will be ignored because the RunID no longer matches.
	probeDlgRunning = false
	setWindowText(hwndProbeRun, "Run")
	enableWindow(hwndProbeSelect, true)
	probeDlgAppendLine("——— stopped ———")
}

// ---------------------------------------------------------------------------
// Output helpers
// ---------------------------------------------------------------------------

func probeDlgAppendLine(line string) {
	existing := getWindowText(hwndProbeOutput)
	var newText string
	if existing == "" {
		newText = line
	} else {
		newText = existing + "\r\n" + line
	}
	setWindowText(hwndProbeOutput, newText)
	n := uintptr(len([]rune(newText)))
	sendMessage(hwndProbeOutput, EM_SETSEL, n, n)
	sendMessage(hwndProbeOutput, EM_SCROLLCARET, 0, 0)
}

func probeDlgAppendDot() {
	existing := getWindowText(hwndProbeOutput)
	if existing == "" {
		return
	}
	newText := existing + "."
	setWindowText(hwndProbeOutput, newText)
	n := uintptr(len([]rune(newText)))
	sendMessage(hwndProbeOutput, EM_SETSEL, n, n)
	sendMessage(hwndProbeOutput, EM_SCROLLCARET, 0, 0)
}

func probeDlgCopyOutput() {
	text := getWindowText(hwndProbeOutput)
	if text == "" {
		return
	}
	copyToClipboard(hwndProbeOutput, text)
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

// showProbeDialog opens the deep probe dialog.
//   - parent: the owner window (main window or host detail dialog).
//   - ip: pre-filled IP address; may be empty.
//   - ipLocked: when true the IP field is read-only (opened from a host dialog).
func showProbeDialog(parent HWND, ip string, ipLocked bool) {
	probeDlgIPLocked = ipLocked
	probeDlgSelectedProbe = nil
	probeDlgRunID = ""
	probeDlgRunning = false
	probeDlgAllProbes = scan.AllDeepProbes()

	title := "Probe"
	if ip != "" {
		title = "Probe \u2014 " + ip
	}

	registerDialogClass("NetScopeProbeDialog", probeDlgWndProc)
	dlg := createAndCenterDialog("NetScopeProbeDialog", title, 524, 400, probeDlgWndProc, parent)
	if dlg == 0 {
		return
	}
	if ip != "" {
		setWindowText(hwndProbeIP, ip)
	}
	setFontAllChildren(dlg, appFont)

	atomic.StoreUintptr(&hwndProbeDlgAtomic, uintptr(dlg))
	runModal(dlg, parent)
	// On close, hwndProbeDlgAtomic is already cleared by WM_CLOSE / idProbeClose.
}
