package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/demicloud/net-sweep/internal/config"
	"github.com/demicloud/net-sweep/internal/sweep"
)

func main() {
	sweep.InitVendorDB()

	cfg, cfgPath, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: %v\n", err)
	}
	if cfgPath != "" {
		fmt.Fprintf(os.Stderr, "config: %s\n", cfgPath)
	}

	// Flags override config values when explicitly provided.
	timeout := flag.Duration("timeout", cfg.Scan.ParseTimeout(), "per-host timeout")
	concurrency := flag.Int("c", cfg.Scan.Concurrency, "max concurrent probes")
	format := flag.String("format", "text", "output format: text, json, csv")
	portsFlag := flag.String("ports", "", "comma-separated ports (overrides config)")
	noPing := flag.Bool("no-ping", !cfg.Scan.PingFirst, "scan all hosts, skip ICMP check")
	noSNMP := flag.Bool("no-snmp", false, "disable SNMP probing")
	noBroadcast := flag.Bool("no-broadcast", false, "disable mDNS/SSDP discovery")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: net-sweep [flags] <target>\n\n")
		fmt.Fprintf(os.Stderr, "  target  single IP or CIDR, e.g. 192.168.1.0/24\n\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(1)
	}
	target := flag.Arg(0)

	scanCfg := cfg.ToSweepConfig()
	scanCfg.Timeout = *timeout
	scanCfg.Concurrency = *concurrency
	scanCfg.PingFirst = !*noPing

	if *portsFlag != "" {
		scanCfg.Ports = parsePorts(*portsFlag)
	}
	if *noSNMP {
		scanCfg.SNMPCommunity = ""
	}
	if *noBroadcast {
		scanCfg.BroadcastListen = 0
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	ch, err := sweep.NewScanner(scanCfg).Scan(ctx, target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	var results []sweep.Result
	for r := range ch {
		if r.Alive {
			results = append(results, r)
			if *format == "text" {
				fmt.Println(r)
			}
		}
	}

	switch *format {
	case "json":
		if err := sweep.WriteJSON(os.Stdout, results); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	case "csv":
		if err := sweep.WriteCSV(os.Stdout, results); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	}
}

func parsePorts(s string) []int {
	var ports []int
	for _, chunk := range strings.Split(s, ",") {
		var p int
		if _, err := fmt.Sscanf(strings.TrimSpace(chunk), "%d", &p); err == nil && p > 0 {
			ports = append(ports, p)
		}
	}
	return ports
}
