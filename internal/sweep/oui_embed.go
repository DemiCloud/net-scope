package sweep

import _ "embed"

// embeddedOUI holds the OUI database compiled into the binary.
// The file is downloaded by `make fetch-oui` and is not tracked in git.
//
//go:embed oui.json
var embeddedOUI []byte
