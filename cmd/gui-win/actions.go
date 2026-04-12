//go:build windows

package guiwin

// ServiceAction describes a URI-based quick-connect action that can be
// launched for a scanned host from the context menu or host detail dialog.
// Actions are pure UI helpers; no network I/O happens here.
type ServiceAction struct {
	Label  string // menu display name
	Scheme string // URI scheme (without "://"); "smb" uses UNC path instead
	Port   int    // default port (informational only)
}

// allServiceActions is the ordered list of action entries shown in menus.
var allServiceActions = []ServiceAction{
	{Label: "Open in Browser (HTTP)",  Scheme: "http",   Port: 80},
	{Label: "Open in Browser (HTTPS)", Scheme: "https",  Port: 443},
	{Label: "SSH",                     Scheme: "ssh",    Port: 22},
	{Label: "Remote Desktop (RDP)",    Scheme: "rdp",    Port: 3389},
	{Label: "FTP",                     Scheme: "ftp",    Port: 21},
	{Label: "SMB / File Share",        Scheme: "smb",    Port: 445},
	{Label: "Telnet",                  Scheme: "telnet", Port: 23},
}

// actionMenuBase is the first WM_COMMAND ID reserved for allServiceActions
// entries in any TrackPopupMenu that uses buildConnectMenu.
const actionMenuBase = 4000

// buildConnectMenu creates a new popup menu populated with allServiceActions.
// The returned HMENU must be destroyed by the caller after use.
func buildConnectMenu() HMENU {
	hm := createPopupMenu()
	for i, a := range allServiceActions {
		appendMenu(hm, MF_STRING, uintptr(actionMenuBase+i), a.Label)
	}
	return hm
}

// launchServiceAction opens the URI for the given action and IP address using
// the default shell handler.
func launchServiceAction(parent HWND, action ServiceAction, ip string) {
	var uri string
	switch action.Scheme {
	case "smb":
		uri = `\\` + ip
	default:
		uri = action.Scheme + "://" + ip
	}
	shellExecute(parent, "open", uri, "", "", SW_SHOW)
}
