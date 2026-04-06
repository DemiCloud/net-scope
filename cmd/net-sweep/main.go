package main

import (
	"github.com/demicloud/net-scope/internal/config"
	"github.com/demicloud/net-scope/internal/sweep"
)

// version is injected at build time: -ldflags "-X main.version=x.y.z"
var version = "dev"

func main() {
	sweep.InitVendorDB(config.DataDir())
	run() // platform-specific dispatch; defined in dispatch_windows.go / dispatch_other.go
}
