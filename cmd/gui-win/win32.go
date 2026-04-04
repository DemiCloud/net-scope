//go:build windows

package main

import (
	"syscall"
	"unsafe"
)

// ---------------------------------------------------------------------------
// Handle types
// ---------------------------------------------------------------------------

type (
	HWND      uintptr
	HINSTANCE uintptr
	HMENU     uintptr
	HBRUSH    uintptr
	HCURSOR   uintptr
	HICON     uintptr
	HANDLE    uintptr
	HFONT     uintptr
	HGDIOBJ   uintptr
)

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const (
	// Window styles
	WS_OVERLAPPED       = 0x00000000
	WS_CAPTION          = 0x00C00000
	WS_SYSMENU          = 0x00080000
	WS_THICKFRAME       = 0x00040000
	WS_MINIMIZEBOX      = 0x00020000
	WS_MAXIMIZEBOX      = 0x00010000
	WS_OVERLAPPEDWINDOW = WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_THICKFRAME | WS_MINIMIZEBOX | WS_MAXIMIZEBOX
	WS_CHILD            = 0x40000000
	WS_VISIBLE          = 0x10000000
	WS_VSCROLL          = 0x00200000
	WS_BORDER           = 0x00800000
	WS_TABSTOP          = 0x00010000

	// Class styles
	CS_HREDRAW = 0x0002
	CS_VREDRAW = 0x0001

	// Edit styles
	ES_AUTOHSCROLL = 0x0080
	ES_MULTILINE   = 0x0004
	ES_AUTOVSCROLL = 0x0040
	ES_READONLY    = 0x0800

	// Button styles / messages
	BS_AUTOCHECKBOX = 0x0003
	BM_GETCHECK     = 0x00F0
	BM_SETCHECK     = 0x00F1
	BST_UNCHECKED   = 0
	BST_CHECKED     = 1

	// System
	CW_USEDEFAULT = ^int32(0x7fffffff) // 0x80000000
	SW_SHOWNORMAL = 1
	COLOR_WINDOW  = 5

	// Messages
	WM_CREATE   = 0x0001
	WM_DESTROY  = 0x0002
	WM_SIZE     = 0x0005
	WM_CLOSE    = 0x0010
	WM_KEYDOWN  = 0x0100
	WM_COMMAND  = 0x0111
	WM_APP      = 0x8000

	// Custom messages
	WM_SCAN_RESULT   = WM_APP + 1
	WM_SCAN_COMPLETE = WM_APP + 2

	// Control IDs
	IDC_TARGET    = 101
	IDC_SCAN      = 103
	IDC_STOP      = 104
	IDC_LIST      = 105
	IDC_STATUS    = 106
	IDC_TABS      = 107
	IDC_LIST_BCAST = 108

	// Menu command IDs
	IDM_FILE_EXIT    = 201
	IDM_OPT_SETTINGS = 202
	IDM_HELP_ABOUT   = 203
	IDM_HELP_FAQ     = 204

	// Null message (used to wake up a modal message loop)
	WM_NULL = 0x0000

	// MessageBox flags and return values
	MB_OK          = 0x00000000
	MB_YESNO       = 0x00000004
	MB_ICONWARNING = 0x00000030

	IDYES = 6
	IDNO  = 7

	// Token access
	TOKEN_QUERY = 0x0008

	// System cursors / icons
	IDC_ARROW = 32512

	// Common controls init flags
	ICC_LISTVIEW_CLASSES = 0x00000001
	ICC_BAR_CLASSES      = 0x00000004

	// ListView window class and styles
	WC_LISTVIEW      = "SysListView32"
	LVS_REPORT       = 0x0001
	LVS_SHOWSELALWAYS = 0x0008

	// ListView extended styles
	LVS_EX_FULLROWSELECT = 0x00000020
	LVS_EX_GRIDLINES     = 0x00000001
	LVS_EX_DOUBLEBUFFER  = 0x00010000

	// ListView messages — always use the W (Unicode) variants.
	// The ANSI variants (+6, +7) interpret pszText as single-byte and will
	// truncate UTF-16 strings to their first byte (e.g. "10.x.x.x" → "1").
	LVM_FIRST                    = 0x1000
	LVM_INSERTCOLUMN             = LVM_FIRST + 97 // LVM_INSERTCOLUMNW
	LVM_INSERTITEM               = LVM_FIRST + 77 // LVM_INSERTITEMW  (NOT +7 which is ANSI)
	LVM_SETITEM                  = LVM_FIRST + 76 // LVM_SETITEMW     (NOT +6 which is ANSI)
	LVM_DELETEALLITEMS           = LVM_FIRST + 9  // no ANSI/W split
	LVM_SETEXTENDEDLISTVIEWSTYLE = LVM_FIRST + 54 // no ANSI/W split

	// LVCOLUMN flags
	LVCF_FMT   = 0x0001
	LVCF_WIDTH = 0x0002
	LVCF_TEXT  = 0x0004
	LVCFMT_LEFT = 0

	// LVITEM flags
	LVIF_TEXT = 0x0001

	// StatusBar messages
	SB_SETTEXT  = 0x0401
	SB_SETPARTS = 0x0404

	// Button notification
	BN_CLICKED = 0

	// Edit messages
	EM_SETSEL = 0x00B1

	// Virtual keys
	VK_CONTROL = 0x11
	VK_KEY_A   = 0x41

	// Tab control
	WC_TABCONTROL  = "SysTabControl32"
	TCM_FIRST      = 0x1300
	TCM_INSERTITEM = TCM_FIRST + 62 // TCM_INSERTITEMW
	TCM_GETCURSEL  = TCM_FIRST + 11
	TCM_ADJUSTRECT = TCM_FIRST + 40
	TCIF_TEXT      = 0x0001

	// WM_NOTIFY and tab notifications
	WM_NOTIFY     = 0x004E
	TCN_SELCHANGE = 0xFFFFFDD9 // (uint32)(-551)

	// Menu flags
	MF_STRING    = 0x00000000
	MF_POPUP     = 0x00000010
	MF_SEPARATOR = 0x00000800

	// Window styles (popup dialogs)
	WS_POPUP        = 0x80000000
	WS_CLIPCHILDREN = 0x02000000

	// Extended window styles
	WS_EX_DLGMODALFRAME = 0x00000001
	WS_EX_CLIENTEDGE    = 0x00000200

	// ShowWindow extras
	SW_SHOW = 5
	SW_HIDE = 0

	// Font / GDI
	WM_SETFONT       = 0x0030
	FW_NORMAL        = 400
	CLEARTYPE_QUALITY = 5

	// Icon IDs (for LoadIconW with NULL hInstance)
	IDI_APPLICATION = 32512

	// LoadImage / CreateIconFromResourceEx flags
	LR_DEFAULTCOLOR = 0x00000000
)

// ---------------------------------------------------------------------------
// Structs
// ---------------------------------------------------------------------------

type WNDCLASSEX struct {
	CbSize        uint32
	Style         uint32
	LpfnWndProc   uintptr
	CbClsExtra    int32
	CbWndExtra    int32
	HInstance     HINSTANCE
	HIcon         HICON
	HCursor       HCURSOR
	HbrBackground HBRUSH
	LpszMenuName  *uint16
	LpszClassName *uint16
	HIconSm       HICON
}

type MSG struct {
	HWnd    HWND
	Message uint32
	_       [4]byte // pad to align WParam on x64
	WParam  uintptr
	LParam  uintptr
	Time    uint32
	Pt      POINT
}

type POINT struct {
	X, Y int32
}

// NMHDR is the header common to all WM_NOTIFY messages.
type NMHDR struct {
	HwndFrom uintptr
	IdFrom   uintptr
	Code     uint32
	_        [4]byte // trailing pad
}

// TCITEM is used to insert/query tab control items.
// Fields after the three uint32s get 4-byte padding before the pointer (x64).
type TCITEM struct {
	Mask        uint32
	DwState     uint32
	DwStateMask uint32
	PszText     *uint16 // offset 16 after compiler padding
	CchTextMax  int32
	IImage      int32
	LParam      uintptr
}

type RECT struct {
	Left, Top, Right, Bottom int32
}

type INITCOMMONCONTROLSEX struct {
	DwSize uint32
	DwICC  uint32
}

type LVCOLUMN struct {
	Mask       uint32
	Fmt        int32
	Cx         int32
	PszText    *uint16
	CchTextMax int32
	ISubItem   int32
	IImage     int32
	IOrder     int32
}

type LVITEM struct {
	Mask       uint32
	IItem      int32
	ISubItem   int32
	State      uint32
	StateMask  uint32
	PszText    *uint16
	CchTextMax int32
	IImage     int32
	LParam     uintptr
}

// ---------------------------------------------------------------------------
// DLL references
// ---------------------------------------------------------------------------

var (
	modUser32   = syscall.NewLazyDLL("user32.dll")
	modKernel32 = syscall.NewLazyDLL("kernel32.dll")
	modComctl32 = syscall.NewLazyDLL("comctl32.dll")

	procRegisterClassExW        = modUser32.NewProc("RegisterClassExW")
	procCreateWindowExW         = modUser32.NewProc("CreateWindowExW")
	procDefWindowProcW          = modUser32.NewProc("DefWindowProcW")
	procGetMessageW             = modUser32.NewProc("GetMessageW")
	procTranslateMessage        = modUser32.NewProc("TranslateMessage")
	procDispatchMessageW        = modUser32.NewProc("DispatchMessageW")
	procPostQuitMessage         = modUser32.NewProc("PostQuitMessage")
	procLoadCursorW             = modUser32.NewProc("LoadCursorW")
	procShowWindow              = modUser32.NewProc("ShowWindow")
	procUpdateWindow            = modUser32.NewProc("UpdateWindow")
	procGetClientRect           = modUser32.NewProc("GetClientRect")
	procMoveWindow              = modUser32.NewProc("MoveWindow")
	procSendMessageW            = modUser32.NewProc("SendMessageW")
	procPostMessageW            = modUser32.NewProc("PostMessageW")
	procGetWindowTextLengthW    = modUser32.NewProc("GetWindowTextLengthW")
	procGetWindowTextW          = modUser32.NewProc("GetWindowTextW")
	procSetWindowTextW          = modUser32.NewProc("SetWindowTextW")
	procEnableWindow            = modUser32.NewProc("EnableWindow")
	procMessageBoxW             = modUser32.NewProc("MessageBoxW")
	procGetKeyState             = modUser32.NewProc("GetKeyState")

	// Menu
	procCreateMenu              = modUser32.NewProc("CreateMenu")
	procCreatePopupMenu         = modUser32.NewProc("CreatePopupMenu")
	procAppendMenuW             = modUser32.NewProc("AppendMenuW")
	procSetMenu                 = modUser32.NewProc("SetMenu")
	procDrawMenuBar             = modUser32.NewProc("DrawMenuBar")

	// Shell (open files/URLs)
	modShell32          = syscall.NewLazyDLL("shell32.dll")
	procShellExecuteW   = modShell32.NewProc("ShellExecuteW")

	// GDI32
	modGdi32          = syscall.NewLazyDLL("gdi32.dll")
	procCreateFontW   = modGdi32.NewProc("CreateFontW")

	// Advapi32 (token/elevation)
	modAdvapi32             = syscall.NewLazyDLL("advapi32.dll")
	procOpenProcessToken    = modAdvapi32.NewProc("OpenProcessToken")
	procGetTokenInformation = modAdvapi32.NewProc("GetTokenInformation")

	procGetModuleHandleW  = modKernel32.NewProc("GetModuleHandleW")
	procGetCurrentProcess = modKernel32.NewProc("GetCurrentProcess")
	procCloseHandle       = modKernel32.NewProc("CloseHandle")

	procEnumChildWindows         = modUser32.NewProc("EnumChildWindows")
	procLoadIconW                = modUser32.NewProc("LoadIconW")
	procCreateIconFromResourceEx = modUser32.NewProc("CreateIconFromResourceEx")
	procGetWindowRect            = modUser32.NewProc("GetWindowRect")
	procDestroyWindow            = modUser32.NewProc("DestroyWindow")

	procInitCommonControlsEx    = modComctl32.NewProc("InitCommonControlsEx")
	procCreateStatusWindowW     = modComctl32.NewProc("CreateStatusWindowW")
)

// ---------------------------------------------------------------------------
// Wrappers
// ---------------------------------------------------------------------------

func registerClassEx(wc *WNDCLASSEX) (uint16, error) {
	r, _, err := procRegisterClassExW.Call(uintptr(unsafe.Pointer(wc)))
	if r == 0 {
		return 0, err
	}
	return uint16(r), nil
}

func createWindowEx(exStyle uint32, className, title string, style uint32, x, y, w, h int32, parent HWND, menu HMENU, inst HINSTANCE) (HWND, error) {
	cn, _ := syscall.UTF16PtrFromString(className)
	tn, _ := syscall.UTF16PtrFromString(title)
	r, _, err := procCreateWindowExW.Call(
		uintptr(exStyle),
		uintptr(unsafe.Pointer(cn)),
		uintptr(unsafe.Pointer(tn)),
		uintptr(style),
		uintptr(x), uintptr(y), uintptr(w), uintptr(h),
		uintptr(parent),
		uintptr(menu),
		uintptr(inst),
		0,
	)
	if r == 0 {
		return 0, err
	}
	return HWND(r), nil
}

func defWindowProc(hwnd HWND, msg uint32, wParam, lParam uintptr) uintptr {
	r, _, _ := procDefWindowProcW.Call(uintptr(hwnd), uintptr(msg), wParam, lParam)
	return r
}

func getMessage(msg *MSG) bool {
	r, _, _ := procGetMessageW.Call(uintptr(unsafe.Pointer(msg)), 0, 0, 0)
	return int32(r) != 0
}

func translateMessage(msg *MSG) {
	procTranslateMessage.Call(uintptr(unsafe.Pointer(msg)))
}

func dispatchMessage(msg *MSG) {
	procDispatchMessageW.Call(uintptr(unsafe.Pointer(msg)))
}

func postQuitMessage(code int32) {
	procPostQuitMessage.Call(uintptr(code))
}

func loadCursor(name uintptr) HCURSOR {
	r, _, _ := procLoadCursorW.Call(0, name)
	return HCURSOR(r)
}

func showWindow(hwnd HWND, cmd int32) {
	procShowWindow.Call(uintptr(hwnd), uintptr(cmd))
}

func updateWindow(hwnd HWND) {
	procUpdateWindow.Call(uintptr(hwnd))
}

func getClientRect(hwnd HWND) RECT {
	var r RECT
	procGetClientRect.Call(uintptr(hwnd), uintptr(unsafe.Pointer(&r)))
	return r
}

func moveWindow(hwnd HWND, x, y, w, h int32) {
	procMoveWindow.Call(uintptr(hwnd), uintptr(x), uintptr(y), uintptr(w), uintptr(h), 1)
}

func sendMessage(hwnd HWND, msg uint32, wParam, lParam uintptr) uintptr {
	r, _, _ := procSendMessageW.Call(uintptr(hwnd), uintptr(msg), wParam, lParam)
	return r
}

func postMessage(hwnd HWND, msg uint32, wParam, lParam uintptr) {
	procPostMessageW.Call(uintptr(hwnd), uintptr(msg), wParam, lParam)
}

func getWindowText(hwnd HWND) string {
	n, _, _ := procGetWindowTextLengthW.Call(uintptr(hwnd))
	if n == 0 {
		return ""
	}
	buf := make([]uint16, n+1)
	procGetWindowTextW.Call(uintptr(hwnd), uintptr(unsafe.Pointer(&buf[0])), n+1)
	return syscall.UTF16ToString(buf)
}

func setWindowText(hwnd HWND, s string) {
	p, _ := syscall.UTF16PtrFromString(s)
	procSetWindowTextW.Call(uintptr(hwnd), uintptr(unsafe.Pointer(p)))
}

func enableWindow(hwnd HWND, enable bool) {
	v := uintptr(0)
	if enable {
		v = 1
	}
	procEnableWindow.Call(uintptr(hwnd), v)
}

func messageBox(hwnd HWND, text, caption string, flags uint32) int32 {
	t, _ := syscall.UTF16PtrFromString(text)
	c, _ := syscall.UTF16PtrFromString(caption)
	r, _, _ := procMessageBoxW.Call(uintptr(hwnd), uintptr(unsafe.Pointer(t)), uintptr(unsafe.Pointer(c)), uintptr(flags))
	return int32(r)
}

// isElevated reports whether the current process has administrator privileges.
func isElevated() bool {
	proc, _, _ := procGetCurrentProcess.Call()
	var token uintptr
	r, _, _ := procOpenProcessToken.Call(proc, TOKEN_QUERY, uintptr(unsafe.Pointer(&token)))
	if r == 0 {
		return false
	}
	defer procCloseHandle.Call(token)

	var elevation uint32
	var retLen uint32
	const tokenElevation = 20 // TokenElevation enum value
	r, _, _ = procGetTokenInformation.Call(
		token,
		tokenElevation,
		uintptr(unsafe.Pointer(&elevation)),
		unsafe.Sizeof(elevation),
		uintptr(unsafe.Pointer(&retLen)),
	)
	return r != 0 && elevation != 0
}

func getModuleHandle() HINSTANCE {
	r, _, _ := procGetModuleHandleW.Call(0)
	return HINSTANCE(r)
}

func initCommonControls() {
	ice := INITCOMMONCONTROLSEX{
		DwSize: uint32(unsafe.Sizeof(INITCOMMONCONTROLSEX{})),
		DwICC:  ICC_LISTVIEW_CLASSES | ICC_BAR_CLASSES,
	}
	procInitCommonControlsEx.Call(uintptr(unsafe.Pointer(&ice)))
}

func createStatusWindow(parent HWND, id uintptr, text string) HWND {
	t, _ := syscall.UTF16PtrFromString(text)
	r, _, _ := procCreateStatusWindowW.Call(
		WS_CHILD|WS_VISIBLE,
		uintptr(unsafe.Pointer(t)),
		uintptr(parent),
		id,
	)
	return HWND(r)
}

// getKeyState returns true if the given virtual key is currently held down.
func getKeyState(vk uintptr) bool {
	r, _, _ := procGetKeyState.Call(vk)
	// High bit of the int16 result means key is down.
	return uint16(r)&0x8000 != 0
}

func getWindowRect(hwnd HWND) RECT {
	var r RECT
	procGetWindowRect.Call(uintptr(hwnd), uintptr(unsafe.Pointer(&r)))
	return r
}

func destroyWindow(hwnd HWND) {
	procDestroyWindow.Call(uintptr(hwnd))
}

// centerOnParent repositions dlg so it is centered over parent on screen.
func centerOnParent(dlg, parent HWND, w, h int32) {
	pr := getWindowRect(parent)
	x := (pr.Left + pr.Right - w) / 2
	y := (pr.Top + pr.Bottom - h) / 2
	moveWindow(dlg, x, y, w, h)
}

func utf16(s string) *uint16 {
	p, _ := syscall.UTF16PtrFromString(s)
	return p
}

func hiword(x uintptr) int32 { return int32(x >> 16) }
func loword(x uintptr) int32 { return int32(x & 0xFFFF) }

func createMenu() HMENU {
	r, _, _ := procCreateMenu.Call()
	return HMENU(r)
}

func createPopupMenu() HMENU {
	r, _, _ := procCreatePopupMenu.Call()
	return HMENU(r)
}

// appendMenu adds an item to menu. For MF_POPUP, pass uintptr(subMenuHandle) as id.
// For MF_STRING, pass the command ID as id.
func appendMenu(menu HMENU, flags uint32, id uintptr, text string) {
	t, _ := syscall.UTF16PtrFromString(text)
	procAppendMenuW.Call(uintptr(menu), uintptr(flags), id, uintptr(unsafe.Pointer(t)))
}

func setMenu(hwnd HWND, menu HMENU) {
	procSetMenu.Call(uintptr(hwnd), uintptr(menu))
}

func drawMenuBar(hwnd HWND) {
	procDrawMenuBar.Call(uintptr(hwnd))
}

// shellExecute opens a file or URL using the shell. Use op="open", SW_SHOW for show.
func shellExecute(hwnd HWND, op, file, params, dir string, show int32) {
	opPtr, _ := syscall.UTF16PtrFromString(op)
	filePtr, _ := syscall.UTF16PtrFromString(file)
	var paramsPtr *uint16
	if params != "" {
		paramsPtr, _ = syscall.UTF16PtrFromString(params)
	}
	var dirPtr *uint16
	if dir != "" {
		dirPtr, _ = syscall.UTF16PtrFromString(dir)
	}
	procShellExecuteW.Call(
		uintptr(hwnd),
		uintptr(unsafe.Pointer(opPtr)),
		uintptr(unsafe.Pointer(filePtr)),
		uintptr(unsafe.Pointer(paramsPtr)),
		uintptr(unsafe.Pointer(dirPtr)),
		uintptr(show),
	)
}

// createUIFont creates a Segoe UI 9pt font suitable for all dialog controls.
// height -12 = 9pt at 96 DPI (the Windows default scaling).
func createUIFont() HFONT {
	face, _ := syscall.UTF16PtrFromString("Segoe UI")
	height := int32(-12) // 9pt at 96 DPI; negative = character height, not cell height
	r, _, _ := procCreateFontW.Call(
		uintptr(height),
		0,                           // average char width (0 = auto)
		0,                           // escapement
		0,                           // orientation
		FW_NORMAL,                   // weight
		0,                           // italic
		0,                           // underline
		0,                           // strikeout
		0,                           // charset  (ANSI_CHARSET)
		0,                           // out precision
		0,                           // clip precision
		CLEARTYPE_QUALITY,           // quality — enables ClearType rendering
		0,                           // pitch and family
		uintptr(unsafe.Pointer(face)),
	)
	return HFONT(r)
}

// setFontAllChildren sends WM_SETFONT to every descendant of parent.
func setFontAllChildren(parent HWND, font HFONT) {
	cb := syscall.NewCallback(func(hwnd, lParam uintptr) uintptr {
		sendMessage(HWND(hwnd), WM_SETFONT, lParam, 1)
		return 1 // continue enumeration
	})
	procEnumChildWindows.Call(uintptr(parent), cb, uintptr(font))
}

// loadSystemIcon loads one of the built-in Windows icons (e.g. IDI_APPLICATION).
func loadSystemIcon(id uintptr) HICON {
	r, _, _ := procLoadIconW.Call(0, id)
	return HICON(r)
}

// insertTab adds a tab item at index idx in a SysTabControl32.
func insertTab(hwnd HWND, idx int32, text string) {
	textPtr, _ := syscall.UTF16PtrFromString(text)
	item := TCITEM{
		Mask:    TCIF_TEXT,
		PszText: textPtr,
	}
	sendMessage(hwnd, TCM_INSERTITEM, uintptr(idx), uintptr(unsafe.Pointer(&item)))
	_ = textPtr // keep alive through syscall
}
