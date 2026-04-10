//go:build windows

// dialog_services.go — legacy shim.
// The unified All Services dialog now lives in dialog_service_detail.go.
// showAllServicesDialog is the entry point called from the Tools menu; it
// delegates to showAllServicesDlg in dialog_service_detail.go.

package guiwin

func showAllServicesDialog(parent HWND) {
	showAllServicesDlg(parent)
}
