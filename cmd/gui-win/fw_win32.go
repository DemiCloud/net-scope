//go:build windows

// Win32 framework layer for package guiwin.
//
// This file contains all Win32 API surface used by the package: handle
// type aliases, numeric constants, structs, DLL procedure references, and
// thin Go wrappers.  There is zero NetScope application logic here.
//
// Goal: fw_win32.go (together with fw_dialog.go) should be self-contained
// enough to be extracted into a standalone module in the future without
// requiring changes to the code within it.
//
// Rule: do NOT add application constants (IDC_*, IDM_*, WM_SCAN_*, …) or
// application-specific helper functions to this file.  Those belong in
// win32.go (app constants) or the relevant dialog / UI files.

package guiwin

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
	HKEY      uintptr
)

// ---------------------------------------------------------------------------
// Constants — pure Win32, no application IDs
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
	WS_HSCROLL          = 0x00100000
	WS_VSCROLL          = 0x00200000
	WS_BORDER           = 0x00800000
	WS_TABSTOP          = 0x00010000
	WS_POPUP            = 0x80000000
	WS_CLIPCHILDREN     = 0x02000000

	// Extended window styles
	WS_EX_DLGMODALFRAME = 0x00000001
	WS_EX_CLIENTEDGE    = 0x00000200
	WS_EX_TOPMOST       = 0x00000008

	// Class styles
	CS_HREDRAW = 0x0002
	CS_VREDRAW = 0x0001

	// Edit styles and notifications
	ES_AUTOHSCROLL = 0x0080
	ES_MULTILINE   = 0x0004
	ES_AUTOVSCROLL = 0x0040
	ES_READONLY    = 0x0800
	EN_CHANGE      = 0x0300

	// Static styles
	SS_LEFT        = 0x0000
	SS_CENTER      = 0x0001
	SS_CENTERIMAGE = 0x0200

	// Button styles / messages
	BS_DEFPUSHBUTTON = 0x0001
	BS_AUTOCHECKBOX  = 0x0003
	BM_GETCHECK      = 0x00F0
	BM_SETCHECK      = 0x00F1
	BST_UNCHECKED    = 0
	BST_CHECKED      = 1

	// System
	CW_USEDEFAULT = ^int32(0x7fffffff) // 0x80000000
	SW_SHOWNORMAL = 1
	SW_SHOW       = 5
	SW_HIDE       = 0
	COLOR_WINDOW  = 5
	COLOR_BTNFACE = 15 // system dialog/button background (light gray)

	// Window messages
	WM_NULL           = 0x0000
	WM_CREATE         = 0x0001
	WM_DESTROY        = 0x0002
	WM_SIZE           = 0x0005
	WM_CLOSE          = 0x0010
	WM_PAINT          = 0x000F
	WM_SETFONT        = 0x0030
	WM_KEYDOWN        = 0x0100
	WM_COMMAND        = 0x0111
	WM_NOTIFY         = 0x004E
	WM_MOUSEMOVE      = 0x0200
	WM_LBUTTONDOWN    = 0x0201
	WM_LBUTTONUP      = 0x0202
	WM_RBUTTONUP      = 0x0205
	WM_CAPTURECHANGED = 0x0215
	WM_CTLCOLOREDIT   = 0x0133
	WM_CTLCOLORSTATIC = 0x0138
	WM_DPICHANGED     = 0x02E0
	WM_APP            = 0x8000

	// Mouse wParam button/modifier flags
	MK_LBUTTON = 0x0001

	// SetWindowLongPtrW nIndex values
	GWLP_WNDPROC = ^uintptr(3) // -4

	// DPI awareness context value for Per-Monitor V2 (Windows 10 1703+).
	DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2 = ^uintptr(3) // -4

	// SetWindowPos flags
	SWP_NOZORDER   = 0x0004
	SWP_NOACTIVATE = 0x0010
	SWP_NOSIZE     = 0x0001
	SWP_NOMOVE     = 0x0002

	// MessageBox flags and return values
	MB_OK           = 0x00000000
	MB_YESNO        = 0x00000004
	MB_ICONWARNING  = 0x00000030
	MB_ICONQUESTION = 0x00000020
	MB_ICONERROR    = 0x00000010
	IDYES           = 6
	IDNO            = 7

	WM_DRAWITEM         = 0x002B // owner-draw control/menu needs painting

	// Owner-draw / custom-draw
	NM_CUSTOMDRAW       = uint32(0xFFFFFFF4) // NM_FIRST(0) - 12
	NM_RCLICK           = uint32(0xFFFFFFFB) // NM_FIRST(0) - 5
	NM_DBLCLK           = uint32(0xFFFFFFFD) // NM_FIRST(0) - 3
	CDDS_PREPAINT       = 0x00000001
	CDDS_ITEMPREPAINT   = 0x00010001
	CDDS_SUBITEM        = 0x00020000
	CDRF_DODEFAULT      = 0x00000000
	CDRF_SKIPDEFAULT    = 0x00000004
	CDRF_NEWFONT        = 0x00000002
	CDRF_NOTIFYITEMDRAW = 0x00000020

	// DrawText format flags
	DT_CENTER     = 0x00000001
	DT_VCENTER    = 0x00000004
	DT_SINGLELINE = 0x00000020
	DT_NOPREFIX   = 0x00000800

	// ComboBox styles and messages
	CBS_SIMPLE       = 0x0001
	CBS_DROPDOWN     = 0x0002
	CBS_DROPDOWNLIST = 0x0003
	CBS_AUTOHSCROLL  = 0x0040
	CBS_SORT         = 0x0100
	CB_ADDSTRING     = 0x0143
	CB_RESETCONTENT  = 0x014B
	CB_GETCURSEL     = 0x0147
	CB_GETLBTEXT     = 0x0148
	CB_GETLBTEXTLEN  = 0x0149
	CB_SETCURSEL     = 0x014E
	CB_FINDSTRINGEXACT = 0x0158
	CBN_SELCHANGE    = 1

	// GDI
	SRCCOPY          = 0x00CC0020
	TRANSPARENT      = 1
	OPAQUE           = 2

	// File open dialog (GetSaveFileNameW)
	OFN_OVERWRITEPROMPT = 0x00000002
	OFN_PATHMUSTEXIST   = 0x00000800

	// Token access
	TOKEN_QUERY = 0x0008

	// System cursors / icons
	IDC_ARROW        = 32512
	IDI_APPLICATION  = 32512
	LR_DEFAULTCOLOR  = 0x00000000

	// Common controls init flags
	ICC_LISTVIEW_CLASSES = 0x00000001
	ICC_BAR_CLASSES      = 0x00000004

	// ListView
	WC_LISTVIEW          = "SysListView32"
	LVS_REPORT           = 0x0001
	LVS_SINGLESEL        = 0x0004
	LVS_SHOWSELALWAYS    = 0x0008
	LVS_EX_FULLROWSELECT  = 0x00000020
	LVS_EX_GRIDLINES      = 0x00000001
	LVS_EX_DOUBLEBUFFER   = 0x00010000
	LVS_EX_HEADERDRAGDROP = 0x00000010
	LVS_EX_MARQUEESELECT  = 0x00008000
	LVM_FIRST                    = 0x1000
	LVM_INSERTCOLUMN             = LVM_FIRST + 97
	LVM_SETCOLUMN                = LVM_FIRST + 96
	LVM_INSERTITEM               = LVM_FIRST + 77
	LVM_SETITEM                  = LVM_FIRST + 76
	LVM_DELETEALLITEMS           = LVM_FIRST + 9
	LVM_SETEXTENDEDLISTVIEWSTYLE = LVM_FIRST + 54
	LVM_HITTEST                  = LVM_FIRST + 18
	LVM_GETITEMTEXT              = LVM_FIRST + 115
	LVM_GETNEXTITEM              = LVM_FIRST + 12
	LVM_GETITEMCOUNT             = LVM_FIRST + 4
	LVM_GETHEADER               = LVM_FIRST + 31
	LVM_SETCOLUMNWIDTH          = LVM_FIRST + 30
	LVNI_SELECTED                = 0x0002
	LVM_GETITEMRECT              = LVM_FIRST + 14
	LVM_SETITEMSTATE             = LVM_FIRST + 43
	LVM_SETSELECTIONMARK         = LVM_FIRST + 67
	LVIS_FOCUSED                 = 0x0001
	LVIS_SELECTED                = 0x0002
	LVIR_BOUNDS                  = 0
	LVHT_ONITEM                  = 0x000E // LVHT_ONITEMICON | LVHT_ONITEMLABEL | LVHT_ONITEMSTATEICON
	LVN_KEYDOWN                  = uint32(0xFFFFFF65) // LVN_FIRST - 55
	LVCF_FMT                     = 0x0001
	LVCF_WIDTH                   = 0x0002
	LVCF_TEXT                    = 0x0004
	LVCFMT_LEFT                  = 0
	LVCFMT_RIGHT                 = 1
	LVCFMT_CENTER                = 2
	LVIF_TEXT                    = 0x0001
	// ListView notifications
	LVN_FIRST       = uint32(0xFFFFFF9C) // -100
	LVN_COLUMNCLICK = uint32(0xFFFFFF94) // LVN_FIRST - 8

	// StatusBar
	SB_SETTEXT    = 0x040B
	SB_SETPARTS   = 0x0404
	SBT_OWNERDRAW = 0x1000 // part drawn by parent via WM_DRAWITEM

	// DrawItem action flags (WM_DRAWITEM ItemAction)
	ODA_DRAWENTIRE = 0x0001

	// Button notification
	BN_CLICKED = 0

	// Edit messages
	EM_SETSEL = 0x00B1

	// Virtual keys
	VK_SHIFT   = 0x10
	VK_CONTROL = 0x11
	VK_RETURN  = 0x0D
	VK_ESCAPE  = 0x1B
	VK_KEY_A   = 0x41
	VK_KEY_C   = 0x43

	// Tab control
	WC_TABCONTROL   = "SysTabControl32"
	TCS_FLATBUTTONS = 0x0008
	TCM_FIRST       = 0x1300
	TCM_INSERTITEM  = TCM_FIRST + 62
	TCM_GETCURSEL   = TCM_FIRST + 11
	TCM_ADJUSTRECT  = TCM_FIRST + 40
	TCIF_TEXT       = 0x0001
	TCN_SELCHANGE   = 0xFFFFFDD9 // (uint32)(-551) cast below

	// Menu flags
	MF_STRING    = 0x00000000
	MF_POPUP     = 0x00000010
	MF_SEPARATOR = 0x00000800
	MF_GRAYED    = 0x00000001
	MF_ENABLED   = 0x00000000

	// Track popup menu flags
	TPM_LEFTALIGN  = 0x0000
	TPM_TOPALIGN   = 0x0000
	TPM_RIGHTALIGN = 0x0004
	TPM_RIGHTBUTTON = 0x0002
	TPM_RETURNCMD  = 0x0100

	// Font / GDI
	FW_NORMAL         = 400
	CLEARTYPE_QUALITY = 5

	// DrawIconEx flags
	DI_NORMAL    = 0x0003

	// Clipboard formats
	CF_DIB = 8

	// GlobalAlloc flags
	GMEM_MOVEABLE = 0x0002

	// Registry
	HKEY_CLASSES_ROOT  uintptr = 0x80000000
	HKEY_CURRENT_USER  uintptr = 0x80000001
	KEY_READ                   = 0x20019
)

// ---------------------------------------------------------------------------
// Structs
// ---------------------------------------------------------------------------

// PAINTSTRUCT is the structure passed to BeginPaint/EndPaint.
// Size on x64: 8 (HDC) + 4 (fErase) + 16 (RECT) + 4 + 4 + 32 (reserved) + 4 (padding) = 72.
type PAINTSTRUCT [72]byte

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
	_        [4]byte
}

// DRAWITEMSTRUCT is sent in the lParam of WM_DRAWITEM for owner-drawn controls.
type DRAWITEMSTRUCT struct {
	CtlType    uint32
	CtlID      uint32
	ItemID     uint32
	ItemAction uint32
	ItemState  uint32
	// Go aligns the next pointer-sized field to 8 bytes automatically (4-byte gap here on 64-bit).
	HwndItem   HWND
	HDC        uintptr
	RcItem     RECT
	ItemData   uintptr
}

// TCITEM is used to insert/query tab control items.
type TCITEM struct {
	Mask        uint32
	DwState     uint32
	DwStateMask uint32
	PszText     *uint16
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

// NMLVCUSTOMDRAW is sent with NM_CUSTOMDRAW for list views.
type NMLVCUSTOMDRAW struct {
	Hdr         NMHDR
	DwDrawStage uint32
	Hdc         uintptr
	Rc          RECT
	DwItemSpec  uintptr
	UItemState  uint32
	_           [4]byte
	LItemlParam uintptr
	ClrText     uint32
	ClrTextBk   uint32
	ISubItem    int32
}

// NMLISTVIEW is sent with LVN_* ListView notifications (e.g. LVN_COLUMNCLICK).
// Only the first three fields are needed; the rest are omitted.
type NMLISTVIEW struct {
	Hdr      NMHDR
	IItem    int32
	ISubItem int32
}

// NMLVKEYDOWN is sent via WM_NOTIFY with code LVN_KEYDOWN when a key is
// pressed while a ListView has focus.
type NMLVKEYDOWN struct {
	Hdr   NMHDR
	WVKey uint16
	_     [2]byte // padding
	Flags uint32
}

// LVHITTESTINFO is passed to LVM_HITTEST.
type LVHITTESTINFO struct {
	Pt       POINT
	Flags    uint32
	IItem    int32
	ISubItem int32
	IGroup   int32
}

// OPENFILENAME is the structure passed to GetSaveFileNameW.
type OPENFILENAME struct {
	LStructSize       uint32
	HwndOwner         HWND
	_                 uintptr
	LpstrFilter       *uint16
	LpstrCustomFilter *uint16
	NMaxCustFilter    uint32
	NFilterIndex      uint32
	LpstrFile         *uint16
	NMaxFile          uint32
	LpstrFileTitle    *uint16
	NMaxFileTitle     uint32
	LpstrInitialDir   *uint16
	LpstrTitle        *uint16
	Flags             uint32
	NFileOffset       uint16
	NFileExtension    uint16
	LpstrDefExt       *uint16
	LCustData         uintptr
	LpfnHook          uintptr
	LpTemplateName    *uint16
	PvReserved        uintptr
	DwReserved        uint32
	FlagsEx           uint32
}

// ---------------------------------------------------------------------------
// DLL references
// ---------------------------------------------------------------------------

var (
	modUser32   = syscall.NewLazyDLL("user32.dll")
	modKernel32 = syscall.NewLazyDLL("kernel32.dll")
	modComctl32 = syscall.NewLazyDLL("comctl32.dll")
	modGdi32    = syscall.NewLazyDLL("gdi32.dll")
	modShell32  = syscall.NewLazyDLL("shell32.dll")
	modComdlg32 = syscall.NewLazyDLL("comdlg32.dll")
	modAdvapi32 = syscall.NewLazyDLL("advapi32.dll")

	procRegisterClassExW             = modUser32.NewProc("RegisterClassExW")
	procCreateWindowExW              = modUser32.NewProc("CreateWindowExW")
	procDefWindowProcW               = modUser32.NewProc("DefWindowProcW")
	procGetMessageW                  = modUser32.NewProc("GetMessageW")
	procTranslateMessage             = modUser32.NewProc("TranslateMessage")
	procDispatchMessageW             = modUser32.NewProc("DispatchMessageW")
	procPostQuitMessage              = modUser32.NewProc("PostQuitMessage")
	procLoadCursorW                  = modUser32.NewProc("LoadCursorW")
	procShowWindow                   = modUser32.NewProc("ShowWindow")
	procUpdateWindow                 = modUser32.NewProc("UpdateWindow")
	procGetClientRect                = modUser32.NewProc("GetClientRect")
	procAdjustWindowRectEx           = modUser32.NewProc("AdjustWindowRectEx")
	procMoveWindow                   = modUser32.NewProc("MoveWindow")
	procSendMessageW                 = modUser32.NewProc("SendMessageW")
	procPostMessageW                 = modUser32.NewProc("PostMessageW")
	procGetWindowTextLengthW         = modUser32.NewProc("GetWindowTextLengthW")
	procGetWindowTextW               = modUser32.NewProc("GetWindowTextW")
	procSetWindowTextW               = modUser32.NewProc("SetWindowTextW")
	procEnableWindow                 = modUser32.NewProc("EnableWindow")
	procMessageBoxW                  = modUser32.NewProc("MessageBoxW")
	procGetKeyState                  = modUser32.NewProc("GetKeyState")
	procSetWindowPos                 = modUser32.NewProc("SetWindowPos")
	procSetProcessDpiAwarenessContext = modUser32.NewProc("SetProcessDpiAwarenessContext")
	procGetDpiForWindow              = modUser32.NewProc("GetDpiForWindow")
	procGetDpiForSystem              = modUser32.NewProc("GetDpiForSystem")
	procCreateMenu                   = modUser32.NewProc("CreateMenu")
	procCreatePopupMenu              = modUser32.NewProc("CreatePopupMenu")
	procAppendMenuW                  = modUser32.NewProc("AppendMenuW")
	procSetMenu                      = modUser32.NewProc("SetMenu")
	procDrawMenuBar                  = modUser32.NewProc("DrawMenuBar")
	procTrackPopupMenu               = modUser32.NewProc("TrackPopupMenu")
	procGetCursorPos                 = modUser32.NewProc("GetCursorPos")
	procDestroyMenu                  = modUser32.NewProc("DestroyMenu")
	procScreenToClient               = modUser32.NewProc("ScreenToClient")
	procGetFocus                     = modUser32.NewProc("GetFocus")
	procGetSysColorBrush             = modUser32.NewProc("GetSysColorBrush")
	procFillRect                     = modUser32.NewProc("FillRect")
	procDrawTextW                    = modUser32.NewProc("DrawTextW")
	procInvalidateRect               = modUser32.NewProc("InvalidateRect")
	procEnumChildWindows             = modUser32.NewProc("EnumChildWindows")
	procLoadIconW                    = modUser32.NewProc("LoadIconW")
	procCreateIconFromResourceEx     = modUser32.NewProc("CreateIconFromResourceEx")
	procGetWindowRect                = modUser32.NewProc("GetWindowRect")
	procDestroyWindow                = modUser32.NewProc("DestroyWindow")
	procSetForegroundWindow          = modUser32.NewProc("SetForegroundWindow")
	procSetFocus                     = modUser32.NewProc("SetFocus")
	procIsWindow                     = modUser32.NewProc("IsWindow")
	procIsChild                      = modUser32.NewProc("IsChild")
	procBeginPaint                   = modUser32.NewProc("BeginPaint")
	procEndPaint                     = modUser32.NewProc("EndPaint")
	procGetDC                        = modUser32.NewProc("GetDC")
	procReleaseDC                    = modUser32.NewProc("ReleaseDC")
	procDrawIconEx                   = modUser32.NewProc("DrawIconEx")
	procDestroyIcon                  = modUser32.NewProc("DestroyIcon")
	procSetWindowLongPtrW            = modUser32.NewProc("SetWindowLongPtrW")
	procCallWindowProcW              = modUser32.NewProc("CallWindowProcW")
	procSetCapture                   = modUser32.NewProc("SetCapture")
	procReleaseCapture               = modUser32.NewProc("ReleaseCapture")
	procOpenClipboard                = modUser32.NewProc("OpenClipboard")
	procCloseClipboard               = modUser32.NewProc("CloseClipboard")
	procEmptyClipboard               = modUser32.NewProc("EmptyClipboard")
	procSetClipboardData             = modUser32.NewProc("SetClipboardData")
	procRegisterClipboardFormatW     = modUser32.NewProc("RegisterClipboardFormatW")

	procShellExecuteW = modShell32.NewProc("ShellExecuteW")

	procCreateFontW      = modGdi32.NewProc("CreateFontW")
	procCreateSolidBrush = modGdi32.NewProc("CreateSolidBrush")
	procDeleteObject     = modGdi32.NewProc("DeleteObject")
	procSelectObject     = modGdi32.NewProc("SelectObject")
	procSetBkColor       = modGdi32.NewProc("SetBkColor")
	procSetTextColor     = modGdi32.NewProc("SetTextColor")
	procSetBkMode        = modGdi32.NewProc("SetBkMode")

	procGetSaveFileNameW = modComdlg32.NewProc("GetSaveFileNameW")

	procGlobalAlloc      = modKernel32.NewProc("GlobalAlloc")
	procGlobalLock       = modKernel32.NewProc("GlobalLock")
	procGlobalUnlock     = modKernel32.NewProc("GlobalUnlock")
	procRtlMoveMemory    = modKernel32.NewProc("RtlMoveMemory")
	procGetModuleHandleW = modKernel32.NewProc("GetModuleHandleW")
	procGetCurrentProcess = modKernel32.NewProc("GetCurrentProcess")
	procCloseHandle      = modKernel32.NewProc("CloseHandle")
	procGetConsoleWindow = modKernel32.NewProc("GetConsoleWindow")

	procOpenProcessToken    = modAdvapi32.NewProc("OpenProcessToken")
	procGetTokenInformation = modAdvapi32.NewProc("GetTokenInformation")
	procRegOpenKeyExW       = modAdvapi32.NewProc("RegOpenKeyExW")
	procRegQueryValueExW    = modAdvapi32.NewProc("RegQueryValueExW")
	procRegCloseKey         = modAdvapi32.NewProc("RegCloseKey")

	procInitCommonControlsEx = modComctl32.NewProc("InitCommonControlsEx")
	procCreateStatusWindowW  = modComctl32.NewProc("CreateStatusWindowW")
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

// adjustWindowRectEx converts a desired client rectangle into the outer window
// rectangle required to achieve that client area, accounting for the title bar,
// border, and extended styles. Pass the window style flags and extended style
// flags used when creating the window. hasMenu should be true if the window has
// a menu bar.
func adjustWindowRectEx(clientRect RECT, style, exStyle uint32, hasMenu bool) RECT {
	r := clientRect
	menu := uintptr(0)
	if hasMenu {
		menu = 1
	}
	procAdjustWindowRectEx.Call(uintptr(unsafe.Pointer(&r)), uintptr(style), menu, uintptr(exStyle))
	return r
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

// getKeyState returns the state of the given virtual key. The high-order bit
// is set (value < 0 as int16) if the key is currently pressed.
func getKeyState(vk int) int16 {
	r, _, _ := procGetKeyState.Call(uintptr(vk))
	return int16(r)
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

func getWindowRect(hwnd HWND) RECT {
	var r RECT
	procGetWindowRect.Call(uintptr(hwnd), uintptr(unsafe.Pointer(&r)))
	return r
}

func destroyWindow(hwnd HWND) {
	procDestroyWindow.Call(uintptr(hwnd))
}

// setWindowLongPtr replaces an attribute of the specified window. Returns the
// previous value of the attribute, or 0 on failure.
func setWindowLongPtr(hwnd HWND, index uintptr, val uintptr) uintptr {
	r, _, _ := procSetWindowLongPtrW.Call(uintptr(hwnd), index, val)
	return r
}

// callWindowProc passes a message to the specified window procedure. Used when
// subclassing a window to forward messages to the original procedure.
func callWindowProc(proc uintptr, hwnd HWND, msg uint32, wParam, lParam uintptr) uintptr {
	r, _, _ := procCallWindowProcW.Call(proc, uintptr(hwnd), uintptr(msg), wParam, lParam)
	return r
}

// setCapture sets the mouse capture to hwnd so that all mouse input goes to it.
func setCapture(hwnd HWND) {
	procSetCapture.Call(uintptr(hwnd))
}

// releaseCapture releases the mouse capture from the current window.
func releaseCapture() {
	procReleaseCapture.Call()
}

// centerOnParent repositions dlg so it is centered over parent on screen.
func centerOnParent(dlg, parent HWND, w, h int32) {
	pr := getWindowRect(parent)
	x := (pr.Left + pr.Right - w) / 2
	y := (pr.Top + pr.Bottom - h) / 2
	moveWindow(dlg, x, y, w, h)
}

// centerWindowOver repositions dlg so it is centered over parent, reading dlg's
// current size from its window rect. Call after the window has been created but
// before it is shown.
func centerWindowOver(dlg, parent HWND) {
	dr := getWindowRect(dlg)
	w := dr.Right - dr.Left
	h := dr.Bottom - dr.Top
	centerOnParent(dlg, parent, w, h)
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

// appendMenu adds an item to menu. For MF_POPUP pass uintptr(subMenuHandle)
// as id; for MF_STRING pass the command ID.
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

// trackPopupMenu displays a context menu at (x,y) in screen coordinates.
// Returns the selected command ID when TPM_RETURNCMD is set (0 = cancelled).
func trackPopupMenu(menu HMENU, flags uint32, x, y int32, hwnd HWND) int32 {
	r, _, _ := procTrackPopupMenu.Call(
		uintptr(menu), uintptr(flags),
		uintptr(x), uintptr(y),
		0, uintptr(hwnd), 0,
	)
	return int32(r)
}

func getCursorPos() POINT {
	var pt POINT
	procGetCursorPos.Call(uintptr(unsafe.Pointer(&pt)))
	return pt
}

func destroyMenu(menu HMENU) {
	procDestroyMenu.Call(uintptr(menu))
}

func getFocus() HWND {
	r, _, _ := procGetFocus.Call()
	return HWND(r)
}

// shellExecute opens a file or URL using the shell.
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

func setProcessDpiAwarenessContext(ctx uintptr) {
	procSetProcessDpiAwarenessContext.Call(ctx)
}

func getDpiForWindow(hwnd HWND) uint32 {
	r, _, _ := procGetDpiForWindow.Call(uintptr(hwnd))
	return uint32(r)
}

func getDpiForSystem() uint32 {
	r, _, _ := procGetDpiForSystem.Call()
	if r == 0 {
		return 96
	}
	return uint32(r)
}

func setWindowPos(hwnd HWND, hwndInsertAfter uintptr, x, y, w, h int32, flags uint32) {
	procSetWindowPos.Call(uintptr(hwnd), hwndInsertAfter,
		uintptr(x), uintptr(y), uintptr(w), uintptr(h), uintptr(flags))
}

// createUIFont creates a Segoe UI Variable Text font scaled to the given DPI.
// Falls back to Segoe UI on Windows 10 and earlier.  10pt at 96 DPI = -13px.
func createUIFont(dpi uint32) HFONT {
	face, _ := syscall.UTF16PtrFromString("Segoe UI Variable Text")
	height := -int32(13 * dpi / 96)
	r, _, _ := procCreateFontW.Call(
		uintptr(height), 0, 0, 0, FW_NORMAL, 0, 0, 0, 0, 0, 0,
		CLEARTYPE_QUALITY, 0,
		uintptr(unsafe.Pointer(face)),
	)
	return HFONT(r)
}

// createMonoFont creates a Consolas 9pt font for fixed-width text areas.
func createMonoFont() HFONT {
	face, _ := syscall.UTF16PtrFromString("Consolas")
	height := int32(-12) // 9pt at 96 DPI; use int32 variable to avoid constant overflow
	r, _, _ := procCreateFontW.Call(
		uintptr(height),
		0, 0, 0, FW_NORMAL, 0, 0, 0, 0, 0, 0,
		CLEARTYPE_QUALITY, 0,
		uintptr(unsafe.Pointer(face)),
	)
	return HFONT(r)
}

// setFontAllChildren sends WM_SETFONT to every descendant of parent.
func setFontAllChildren(parent HWND, font HFONT) {
	cb := syscall.NewCallback(func(hwnd, lParam uintptr) uintptr {
		sendMessage(HWND(hwnd), WM_SETFONT, lParam, 1)
		return 1
	})
	procEnumChildWindows.Call(uintptr(parent), cb, uintptr(font))
}

// loadSystemIcon loads one of the built-in Windows icons.
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
	_ = textPtr
}

func createSolidBrush(color uint32) HBRUSH {
	r, _, _ := procCreateSolidBrush.Call(uintptr(color))
	return HBRUSH(r)
}

func deleteObject(obj uintptr) {
	procDeleteObject.Call(obj)
}

func setTextColor(hdc uintptr, color uint32) uint32 {
	r, _, _ := procSetTextColor.Call(hdc, uintptr(color))
	return uint32(r)
}

func setBkColor(hdc uintptr, color uint32) uint32 {
	r, _, _ := procSetBkColor.Call(hdc, uintptr(color))
	return uint32(r)
}

func setBkMode(hdc uintptr, mode int32) {
	procSetBkMode.Call(hdc, uintptr(mode))
}

func fillRect(hdc uintptr, rc *RECT, brush HBRUSH) {
	procFillRect.Call(hdc, uintptr(unsafe.Pointer(rc)), uintptr(brush))
}

func drawText(hdc uintptr, text string, rc *RECT, format uint32) {
	t, _ := syscall.UTF16PtrFromString(text)
	procDrawTextW.Call(hdc, uintptr(unsafe.Pointer(t)), ^uintptr(0),
		uintptr(unsafe.Pointer(rc)), uintptr(format))
}

// getSysColorBrush returns a cached system-color brush. Do NOT call
// deleteObject on the returned value — it is owned by the system.
func getSysColorBrush(colorIndex int) HBRUSH {
	r, _, _ := procGetSysColorBrush.Call(uintptr(colorIndex))
	return HBRUSH(r)
}

// selectObject selects an object (pen, brush, font, …) into a DC and returns
// the previously selected object of the same type.
func selectObject(hdc, obj uintptr) uintptr {
	r, _, _ := procSelectObject.Call(hdc, obj)
	return r
}

// invalidateRect marks a rectangle (or the entire client area when rc is nil)
// as needing repaint. If erase is true, the background is erased first.
func invalidateRect(hwnd HWND, rc *RECT, erase bool) {
	var eraseInt uintptr
	if erase {
		eraseInt = 1
	}
	var rcPtr uintptr
	if rc != nil {
		rcPtr = uintptr(unsafe.Pointer(rc))
	}
	procInvalidateRect.Call(uintptr(hwnd), rcPtr, eraseInt)
}

// getSaveFileName shows a "Save As" dialog. Returns the chosen path or "".
func getSaveFileName(owner HWND, title, defExt, filter string) string {
	buf := make([]uint16, 1024)
	titlePtr, _ := syscall.UTF16PtrFromString(title)
	extPtr, _ := syscall.UTF16PtrFromString(defExt)
	filterRunes := syscall.StringToUTF16(filter)
	for i, c := range filterRunes {
		if c == '|' {
			filterRunes[i] = 0
		}
	}
	ofn := OPENFILENAME{
		LStructSize: uint32(unsafe.Sizeof(OPENFILENAME{})),
		HwndOwner:   owner,
		LpstrFilter: &filterRunes[0],
		LpstrFile:   &buf[0],
		NMaxFile:    uint32(len(buf)),
		LpstrTitle:  titlePtr,
		LpstrDefExt: extPtr,
		Flags:       OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST,
	}
	r, _, _ := procGetSaveFileNameW.Call(uintptr(unsafe.Pointer(&ofn)))
	if r == 0 {
		return ""
	}
	return syscall.UTF16ToString(buf)
}

func setForegroundWindow(hwnd HWND) {
	procSetForegroundWindow.Call(uintptr(hwnd))
}

func setFocus(hwnd HWND) {
	procSetFocus.Call(uintptr(hwnd))
}

func isWindow(hwnd HWND) bool {
	r, _, _ := procIsWindow.Call(uintptr(hwnd))
	return r != 0
}

func isChild(parent, hwnd HWND) bool {
	r, _, _ := procIsChild.Call(uintptr(parent), uintptr(hwnd))
	return r != 0
}

func beginPaint(hwnd HWND, ps *PAINTSTRUCT) uintptr {
	r, _, _ := procBeginPaint.Call(uintptr(hwnd), uintptr(unsafe.Pointer(ps)))
	return r
}

func endPaint(hwnd HWND, ps *PAINTSTRUCT) {
	procEndPaint.Call(uintptr(hwnd), uintptr(unsafe.Pointer(ps)))
}

func getDC(hwnd HWND) uintptr {
	r, _, _ := procGetDC.Call(uintptr(hwnd))
	return r
}

func releaseDC(hwnd HWND, hdc uintptr) {
	procReleaseDC.Call(uintptr(hwnd), hdc)
}

// drawIconEx renders hIcon into hdc at (x,y) sized cx×cy.
// Pass 0 for ani (step) and bg (brush); flags = DI_NORMAL for normal rendering.
func drawIconEx(hdc uintptr, x, y int32, hIcon HICON, cx, cy int32, ani uint32, bg HBRUSH, flags uint32) {
	procDrawIconEx.Call(hdc, uintptr(x), uintptr(y), uintptr(hIcon),
		uintptr(cx), uintptr(cy), uintptr(ani), uintptr(bg), uintptr(flags))
}

func destroyIcon(hIcon HICON) {
	procDestroyIcon.Call(uintptr(hIcon))
}

func openClipboard(owner HWND) bool {
	r, _, _ := procOpenClipboard.Call(uintptr(owner))
	return r != 0
}

func closeClipboard() {
	procCloseClipboard.Call()
}

func emptyClipboard() {
	procEmptyClipboard.Call()
}

func setClipboardData(format uint32, hMem uintptr) uintptr {
	r, _, _ := procSetClipboardData.Call(uintptr(format), hMem)
	return r
}

// registerClipboardFormat registers a named clipboard format and returns its ID.
// Returns 0 on failure.
func registerClipboardFormat(name string) uint32 {
	ptr, _ := syscall.UTF16PtrFromString(name)
	r, _, _ := procRegisterClipboardFormatW.Call(uintptr(unsafe.Pointer(ptr)))
	return uint32(r)
}

func globalAlloc(flags uint32, size uintptr) uintptr {
	r, _, _ := procGlobalAlloc.Call(uintptr(flags), size)
	return r
}

func globalLock(hMem uintptr) uintptr {
	r, _, _ := procGlobalLock.Call(hMem)
	return r
}

func globalUnlock(hMem uintptr) {
	procGlobalUnlock.Call(hMem)
}

func getConsoleWindow() HWND {
	r, _, _ := procGetConsoleWindow.Call()
	return HWND(r)
}

// ---------------------------------------------------------------------------
// DPI / scaling
// ---------------------------------------------------------------------------

// currentDPI is the DPI of the monitor containing the main window.
// Updated in WM_DPICHANGED; initialised from GetDpiForWindow in WM_CREATE.
var currentDPI uint32 = 96

// scale converts a 96-DPI logical pixel value to the current physical pixel value.
func scale(n int32) int32 {
	return int32(uint32(n) * currentDPI / 96)
}

// ---------------------------------------------------------------------------
// Registry helpers
// ---------------------------------------------------------------------------

// regReadStringValue opens hive\path and returns the string value named
// valueName (pass "" for the default value). Returns "" on any error.
func regReadStringValue(hive uintptr, path, valueName string) string {
	keyPath, _ := syscall.UTF16PtrFromString(path)
	var hk HKEY
	ret, _, _ := procRegOpenKeyExW.Call(
		hive,
		uintptr(unsafe.Pointer(keyPath)),
		0,
		KEY_READ,
		uintptr(unsafe.Pointer(&hk)),
	)
	if ret != 0 {
		return ""
	}
	defer procRegCloseKey.Call(uintptr(hk))

	vn, _ := syscall.UTF16PtrFromString(valueName)
	var bufLen uint32 = 2048
	buf := make([]uint16, bufLen/2)
	ret, _, _ = procRegQueryValueExW.Call(
		uintptr(hk),
		uintptr(unsafe.Pointer(vn)),
		0,
		0,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&bufLen)),
	)
	if ret != 0 {
		return ""
	}
	return syscall.UTF16ToString(buf)
}

// regReadOpenCommand returns the shell/open/command string that Windows will
// actually use for the given URL scheme.
//
// On Windows 10/11 the user's default browser is stored in
// HKCU\...\UrlAssociations\{scheme}\UserChoice\ProgId, not in
// HKCR\{scheme}\shell\open\command (which reflects the system-level fallback).
// We follow the same lookup chain that ShellExecute uses:
//
//  1. HKCU UserChoice ProgId → HKCR\{progId}\shell\open\command
//  2. Fallback: HKCR\{scheme}\shell\open\command
func regReadOpenCommand(scheme string) string {
	// Step 1: user-configured default (Windows 10/11 default-apps mechanism).
	progID := regReadStringValue(
		HKEY_CURRENT_USER,
		`Software\Microsoft\Windows\Shell\Associations\UrlAssociations\`+scheme+`\UserChoice`,
		"ProgId",
	)
	if progID != "" {
		if cmd := regReadStringValue(HKEY_CLASSES_ROOT, progID+`\shell\open\command`, ""); cmd != "" {
			return cmd
		}
	}
	// Step 2: system-level fallback.
	return regReadStringValue(HKEY_CLASSES_ROOT, scheme+`\shell\open\command`, "")
}
