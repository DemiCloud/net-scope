//go:build with_oui

package scan

import _ "embed"

// embeddedOUI holds the OUI database compiled into the binary.
// The file is downloaded by `make fetch-oui` and is not tracked in git.
// This file is only compiled when the `with_oui` build tag is set (done
// automatically by the Makefile after fetch-oui runs successfully).
//
//go:embed oui.json.gz
var embeddedOUI []byte
