package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/demicloud/net-sweep/internal/config"
	"github.com/demicloud/net-sweep/internal/sweep"
	"github.com/spf13/pflag"
)

// version is injected at build time via -ldflags "-X main.version=..."
var version = "dev"

// ANSI colour escapes — disabled automatically on non-TTY (Windows cmd, pipes).
var (
	colReset  = "\033[0m"
	colBold   = "\033[1m"
	colGreen  = "\033[32m"
	colYellow = "\033[33m"
	colCyan   = "\033[36m"
	colGray   = "\033[90m"
	colRed    = "\033[31m"
)

func init() {
	// Disable colours when stdout is not a terminal (pipe / file redirection).
	if fi, err := os.Stdout.Stat(); err != nil || (fi.Mode()&os.ModeCharDevice) == 0 {
		colReset = ""
		colBold = ""
		colGreen = ""
		colYellow = ""
		colCyan = ""
		colGray = ""
		colRed = ""
	}
}

func main() {
	sweep.InitVendorDB()

	cfg, cfgPath, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: %v\n", err)
	}
	if cfgPath != "" {
		fmt.Fprintf(os.Stderr, "%sconfig:%s %s\n", colGray, colReset, cfgPath)
	}

	// GNU-style long flags (pflag) with short aliases where useful.
	fs := pflag.NewFlagSet("net-sweep", pflag.ContinueOnError)
	fs.SortFlags = false

	timeout     := fs.DurationP("timeout", "t", cfg.Scan.ParseTimeout(), "per-host probe timeout")
	concurrency := fs.IntP("concurrency", "c", cfg.Scan.Concurrency, "maximum concurrent probes")
	format      := fs.StringP("format", "f", "text", "output format: text, json, csv")
	output      := fs.StringP("output", "o", "", "write output to `file` (default: stdout)")
	portsFlag   := fs.StringP("ports", "p", "", "comma-separated TCP ports to scan (overrides config)")
	noPing      := fs.Bool("no-ping", !cfg.Scan.PingFirst, "scan all IPs without ICMP pre-check")
	noSNMP      := fs.Bool("no-snmp", false, "disable SNMP probing")
	noBroadcast := fs.Bool("no-broadcast", false, "disable mDNS/SSDP discovery")
	noBanner    := fs.Bool("no-banner", false, "disable service banner grabbing")
	noNetBIOS   := fs.Bool("no-netbios", false, "disable NetBIOS name queries")
	iface       := fs.StringP("interface", "i", cfg.Scan.Interface, "network interface for ARP (auto-detect if empty)")
	snmpComm    := fs.String("snmp-community", cfg.Scan.SNMPCommunity, "SNMP v2c community string")
	showDown    := fs.Bool("show-down", false, "include non-responding hosts in text output")
	showVersion := fs.BoolP("version", "V", false, "print version and exit")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: net-sweep [OPTIONS] <target>\n\n")
		fmt.Fprintf(os.Stderr, "  <target>  single IP or CIDR (e.g. 192.168.1.0/24, 10.0.0.5)\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		fs.PrintDefaults()
	}

	if err := fs.Parse(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		fs.Usage()
		os.Exit(2)
	}

	if *showVersion {
		fmt.Printf("net-sweep %s\n", version)
		os.Exit(0)
	}

	if fs.NArg() != 1 {
		fs.Usage()
		os.Exit(2)
	}
	target := fs.Arg(0)

	// Validate flags.
	if *timeout < 50*time.Millisecond || *timeout > 5*time.Minute {
		fmt.Fprintln(os.Stderr, "error: --timeout must be between 50ms and 5m")
		os.Exit(2)
	}
	if *concurrency < 1 || *concurrency > 65535 {
		fmt.Fprintln(os.Stderr, "error: --concurrency must be between 1 and 65535")
		os.Exit(2)
	}
	validFormats := map[string]bool{"text": true, "json": true, "csv": true}
	if !validFormats[*format] {
		fmt.Fprintf(os.Stderr, "error: unknown format %q (choose text, json, or csv)\n", *format)
		os.Exit(2)
	}

	// Resolve output writer.
	var out io.Writer = os.Stdout
	if *output != "" {
		f, err := os.Create(*output)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		defer f.Close()
		out = f
	}

	// WAN safety: warn if the target is not an RFC1918/link-local range.
	if !sweep.IsPrivate(target) {
		fmt.Fprintf(os.Stderr,
			"%swarning:%s target %q is not an RFC1918/private address.\n"+
				"         Scanning hosts you do not own may be illegal. Proceed? [y/N] ",
			colYellow, colReset, target)
		var answer string
		fmt.Fscanln(os.Stdin, &answer)
		if answer != "y" && answer != "Y" {
			fmt.Fprintln(os.Stderr, "aborted.")
			os.Exit(1)
		}
	}

	scanCfg := cfg.ToSweepConfig()
	scanCfg.Timeout = *timeout
	scanCfg.Concurrency = *concurrency
	scanCfg.PingFirst = !*noPing
	scanCfg.Interface = *iface
	scanCfg.SNMPCommunity = *snmpComm

	if *portsFlag != "" {
		scanCfg.Ports = parsePorts(*portsFlag)
	}
	if *noSNMP {
		scanCfg.SNMPCommunity = ""
	}
	if *noBroadcast {
		scanCfg.BroadcastListen = 0
	}
	if *noBanner {
		scanCfg.BannerGrab = false
	}
	if *noNetBIOS {
		scanCfg.NetBIOS = false
	}

	// Expand target early so we know total count for progress indicator.
	hosts, err := sweep.ExpandTarget(target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	total := len(hosts)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	ch, err := sweep.NewScanner(scanCfg).Scan(ctx, target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	if *format == "text" {
		printHeader()
	}

	var results []sweep.Result
	done := 0
	found := 0

	for r := range ch {
		done++
		if r.Alive {
			found++
			results = append(results, r)
		}

		if *format == "text" {
			if r.Alive {
				printResult(out, r)
			} else if *showDown {
				fmt.Fprintf(out, "%s%-16s%s  down\n", colGray, r.IP, colReset)
			}
			// Progress on stderr so it doesn't pollute piped stdout.
			pct := done * 100 / total
			fmt.Fprintf(os.Stderr, "\r%s[%3d%%] %d/%d probed  %s%d alive%s   ",
				colGray, pct, done, total, colGreen, found, colReset)
		}
	}

	if *format == "text" {
		fmt.Fprintf(os.Stderr, "\r%s\r", strings.Repeat(" ", 60)) // clear progress line
		fmt.Fprintf(os.Stderr, "%sDone.%s %d/%d hosts alive.\n", colBold, colReset, found, total)
	}

	switch *format {
	case "json":
		if err := sweep.WriteJSON(out, results); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	case "csv":
		if err := sweep.WriteCSV(out, results); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	}
}

func printHeader() {
	fmt.Printf("%s%-16s  %-30s  %-17s  %-20s  %-8s  %-10s  %-12s  %s%s\n",
		colBold,
		"IP", "Hostname / NetBIOS", "MAC", "Vendor", "Latency", "OS", "Ports", "Banners / SNMP",
		colReset)
	fmt.Println(strings.Repeat("─", 140))
}

func printResult(w io.Writer, r sweep.Result) {
	hostname := r.Hostname
	if hostname == "" && r.NetBIOS != "" {
		hostname = r.NetBIOS
	}
	if hostname == "" {
		hostname = "—"
	}

	mac := "—"
	if r.MAC != nil {
		mac = r.MAC.String()
	}

	vendor := r.Vendor
	if vendor == "" {
		vendor = "—"
	}
	if len(vendor) > 20 {
		vendor = vendor[:18] + "…"
	}

	latency := "—"
	if r.Latency > 0 {
		latency = r.Latency.Round(time.Millisecond).String()
	}

	osStr := string(r.OS)
	if osStr == "" {
		osStr = "—"
	}

	var ports []string
	for _, p := range r.OpenPorts {
		ports = append(ports, fmt.Sprintf("%d", p))
	}
	portStr := "—"
	if len(ports) > 0 {
		portStr = strings.Join(ports, ",")
	}

	// Build extras: banners + SNMP on one line
	var extras []string
	for _, b := range []struct{ label, val string }{
		{"SSH", r.Banner.SSH}, {"HTTP", r.Banner.HTTP}, {"HTTPS", r.Banner.HTTPS},
		{"FTP", r.Banner.FTP}, {"SMTP", r.Banner.SMTP}, {"Telnet", r.Banner.Telnet},
	} {
		if b.val != "" {
			extras = append(extras, fmt.Sprintf("%s%s:%s %s", colCyan, b.label, colReset, b.val))
		}
	}
	if r.SNMP != nil {
		snmpStr := r.SNMP.SysDescr
		if r.SNMP.SysName != "" {
			snmpStr = r.SNMP.SysName + ": " + snmpStr
		}
		if snmpStr != "" {
			extras = append(extras, fmt.Sprintf("%sSNMP:%s %s", colYellow, colReset, snmpStr))
		}
	}
	extraStr := strings.Join(extras, "  ")

	fmt.Fprintf(w, "%s%-16s%s  %-30s  %s%-17s%s  %-20s  %-8s  %s%-10s%s  %-12s  %s\n",
		colGreen, r.IP, colReset,
		hostname,
		colGray, mac, colReset,
		vendor,
		latency,
		colYellow, osStr, colReset,
		portStr,
		extraStr,
	)

	// Print mDNS/SSDP services indented on subsequent lines.
	for _, svc := range r.Services {
		name := svc.Name
		if name == "" {
			name = svc.Type
		}
		fmt.Fprintf(w, "%s  └ [%s] %s (%s)%s\n", colGray, svc.Source, name, svc.Type, colReset)
	}
}

func parsePorts(s string) []int {
	var ports []int
	for _, chunk := range strings.Split(s, ",") {
		var p int
		if _, err := fmt.Sscanf(strings.TrimSpace(chunk), "%d", &p); err == nil && p > 0 && p <= 65535 {
			ports = append(ports, p)
		}
	}
	return ports
}

