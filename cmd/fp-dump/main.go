// fp-dump probes a single host and prints all raw fingerprint signals as JSON.
// Useful for inspecting exactly what data guessOS() sees and for crafting new
// detection rules.
//
// Usage:
//
//	go run ./cmd/fp-dump/ <ip>
//	go run ./cmd/fp-dump/ --timeout 3s <ip>
//
// Requires elevated privileges (CAP_NET_RAW / root) for the SYN probe and ICMP.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/demicloud/net-scope/internal/scan"
	"github.com/spf13/pflag"
)

func main() {
	fs := pflag.NewFlagSet("fp-dump", pflag.ContinueOnError)
	timeout := fs.DurationP("timeout", "t", 3*time.Second, "per-probe timeout")
	snmpComm := fs.String("snmp-community", "public", "SNMP v2c community string")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: fp-dump [OPTIONS] <ip>\n\nOptions:\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		fs.Usage()
		os.Exit(2)
	}
	if fs.NArg() != 1 {
		fs.Usage()
		os.Exit(2)
	}
	target := fs.Arg(0)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	cfg := scan.DefaultConfig()
	cfg.Timeout = *timeout
	cfg.Concurrency = 1
	cfg.PingFirst = false
	cfg.SNMPCommunity = *snmpComm
	cfg.BroadcastListen = 3 * time.Second
	cfg.BannerGrab = true
	cfg.NetBIOS = true
	// Scan a wide set of ports so banners and SYN probe have candidates.
	cfg.Ports = []int{21, 22, 23, 25, 53, 80, 443, 445, 8080, 8443, 8888, 161, 3389}

	ch, err := scan.NewScanner(cfg).Scan(ctx, target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	var result scan.Result
	for r := range ch {
		result = r
	}

	out := buildOutput(result)
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		fmt.Fprintf(os.Stderr, "error encoding JSON: %v\n", err)
		os.Exit(1)
	}
}

type fpOutput struct {
	IP          string   `json:"ip"`
	Alive       bool     `json:"alive"`
	MAC         string   `json:"mac,omitempty"`
	Vendor      string   `json:"vendor,omitempty"`
	Hostname    string   `json:"hostname,omitempty"`
	NetBIOS     string   `json:"netbios,omitempty"`
	LatencyMs   int64    `json:"latency_ms,omitempty"`
	OpenPorts   []int    `json:"open_ports,omitempty"`
	OS          string   `json:"os"`
	OSConfidence uint8   `json:"os_confidence"`

	// Raw signals guessOS() uses:
	ICMP_TTL uint8    `json:"icmp_ttl,omitempty"`
	SYN      *fpSYN   `json:"syn_probe,omitempty"`
	Banner   *fpBanner `json:"banner,omitempty"`
	SNMP     *fpSNMP   `json:"snmp,omitempty"`
	Services []fpService `json:"services,omitempty"`
}

type fpSYN struct {
	WindowSize uint16 `json:"window_size"`
	Options    string `json:"options"`
}

type fpBanner struct {
	SSH    string `json:"ssh,omitempty"`
	HTTP   string `json:"http,omitempty"`
	HTTPS  string `json:"https,omitempty"`
	FTP    string `json:"ftp,omitempty"`
	SMTP   string `json:"smtp,omitempty"`
	Telnet string `json:"telnet,omitempty"`
}

type fpSNMP struct {
	SysDescr    string `json:"sys_descr,omitempty"`
	SysName     string `json:"sys_name,omitempty"`
	SysLocation string `json:"sys_location,omitempty"`
	SysContact  string `json:"sys_contact,omitempty"`
}

type fpService struct {
	Source  string   `json:"source"`
	Name    string   `json:"name,omitempty"`
	Type    string   `json:"type,omitempty"`
	Details []string `json:"details,omitempty"`
}

func buildOutput(r scan.Result) fpOutput {
	out := fpOutput{
		IP:           r.IP.String(),
		Alive:        r.Alive,
		Vendor:       r.Vendor,
		Hostname:     r.Hostname,
		NetBIOS:      r.NetBIOS,
		LatencyMs:    r.Latency.Milliseconds(),
		OpenPorts:    r.OpenPorts,
		OS:           string(r.OS),
		OSConfidence: r.OSConfidence,
		ICMP_TTL:     r.TTL,
	}
	if r.MAC != nil {
		out.MAC = r.MAC.String()
	}

	if r.SYNProbe.WindowSize > 0 {
		out.SYN = &fpSYN{
			WindowSize: r.SYNProbe.WindowSize,
			Options:    r.SYNProbe.Options,
		}
	}

	b := r.Banner
	if b.SSH != "" || b.HTTP != "" || b.HTTPS != "" || b.FTP != "" || b.SMTP != "" || b.Telnet != "" {
		out.Banner = &fpBanner{
			SSH: b.SSH, HTTP: b.HTTP, HTTPS: b.HTTPS,
			FTP: b.FTP, SMTP: b.SMTP, Telnet: b.Telnet,
		}
	}

	if r.SNMP != nil {
		out.SNMP = &fpSNMP{
			SysDescr:    r.SNMP.SysDescr,
			SysName:     r.SNMP.SysName,
			SysLocation: r.SNMP.SysLocation,
			SysContact:  r.SNMP.SysContact,
		}
	}

	for _, svc := range r.Services {
		out.Services = append(out.Services, fpService{
			Source:  svc.Source,
			Name:    svc.Name,
			Type:    svc.Type,
			Details: svc.Details,
		})
	}

	return out
}
