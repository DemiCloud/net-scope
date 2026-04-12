package main

import (
	"github.com/demicloud/net-scope/internal/config"
	"github.com/demicloud/net-scope/internal/probes"
	"github.com/demicloud/net-scope/internal/scan"
)

// version is injected at build time: -ldflags "-X main.version=x.y.z"
var version = "dev"

func main() {
	scan.InitVendorDB(config.DataDir())
	probes.Register() // populate the deep probe registry before any service connection
	run()             // platform-specific dispatch; defined in dispatch_windows.go / dispatch_other.go
}
