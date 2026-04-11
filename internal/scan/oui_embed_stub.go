//go:build !with_oui

package scan

// embeddedOUI is empty when built without `make fetch-oui`.
// Vendor lookup will return "" for all MACs; use `make linux/windows/bsd`
// to get a binary with the full MAC vendor database embedded.
var embeddedOUI = []byte{}
