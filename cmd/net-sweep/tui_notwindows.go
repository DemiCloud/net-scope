//go:build !windows

package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/demicloud/net-sweep/internal/config"
	"github.com/demicloud/net-sweep/internal/sweep"
	"github.com/spf13/pflag"
)

// ---------------------------------------------------------------------------
// Tea messages
// ---------------------------------------------------------------------------

type tuiResultMsg sweep.Result
type tuiDoneMsg struct{}
type tuiErrMsg struct{ err error }

// ---------------------------------------------------------------------------
// Styles
// ---------------------------------------------------------------------------

var (
	tuiStyleHeader   = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("39"))
	tuiStyleAlive    = lipgloss.NewStyle().Foreground(lipgloss.Color("82"))
	tuiStyleDim      = lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
	tuiStyleBanner   = lipgloss.NewStyle().Foreground(lipgloss.Color("214"))
	tuiStyleDivider  = lipgloss.NewStyle().Foreground(lipgloss.Color("237"))
	tuiStyleDone     = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("46"))
	tuiStyleErr      = lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Bold(true)
	tuiStyleProgress = lipgloss.NewStyle().Foreground(lipgloss.Color("39"))
)

// ---------------------------------------------------------------------------
// Model
// ---------------------------------------------------------------------------

type tuiModel struct {
	target   string
	total    int
	done     int
	found    int
	results  []sweep.Result
	finished bool
	scanErr  error
	width    int
	cancel   context.CancelFunc
}

func (m tuiModel) Init() tea.Cmd { return nil }

func (m tuiModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			if m.cancel != nil {
				m.cancel()
			}
			return m, tea.Quit
		}
	case tuiResultMsg:
		r := sweep.Result(msg)
		m.done++
		if r.Alive {
			m.found++
			m.results = append(m.results, r)
		}
	case tuiDoneMsg:
		m.finished = true
		return m, tea.Quit
	case tuiErrMsg:
		m.scanErr = msg.err
		m.finished = true
		return m, tea.Quit
	}
	return m, nil
}

func (m tuiModel) View() string {
	var b strings.Builder

	b.WriteString(tuiStyleHeader.Render(fmt.Sprintf(
		" net-sweep  %s  %d/%d probed  %d alive",
		m.target, m.done, m.total, m.found,
	)))
	b.WriteByte('\n')

	if !m.finished && m.total > 0 {
		pct := m.done * 40 / m.total
		bar := strings.Repeat("█", pct) + strings.Repeat("░", 40-pct)
		pctVal := m.done * 100 / m.total
		b.WriteString(tuiStyleProgress.Render(fmt.Sprintf(" [%s] %d%%", bar, pctVal)))
		b.WriteByte('\n')
	}

	b.WriteString(tuiStyleDivider.Render(strings.Repeat("─", tuiClamp(m.width-2, 40, 160))))
	b.WriteByte('\n')
	b.WriteString(tuiStyleHeader.Render(fmt.Sprintf(
		" %-16s  %-28s  %-17s  %-20s  %-8s  %-10s  %-12s",
		"IP", "Hostname/NetBIOS", "MAC", "Vendor", "Latency", "OS", "Ports",
	)))
	b.WriteByte('\n')
	b.WriteString(tuiStyleDivider.Render(strings.Repeat("─", tuiClamp(m.width-2, 40, 160))))
	b.WriteByte('\n')

	for _, r := range m.results {
		b.WriteString(tuiRenderRow(r))
		b.WriteByte('\n')
	}

	if m.finished {
		if m.scanErr != nil {
			b.WriteString(tuiStyleErr.Render(" Error: " + m.scanErr.Error()))
		} else {
			b.WriteString(tuiStyleDone.Render(fmt.Sprintf(" ✓ Scan complete — %d/%d hosts alive", m.found, m.total)))
		}
		b.WriteString(tuiStyleDim.Render("  (press q to exit)"))
		b.WriteByte('\n')
	} else {
		b.WriteString(tuiStyleDim.Render(" scanning…  press q to abort"))
		b.WriteByte('\n')
	}
	return b.String()
}

func tuiRenderRow(r sweep.Result) string {
	hostname := r.Hostname
	if hostname == "" && r.NetBIOS != "" {
		hostname = r.NetBIOS
	}
	if hostname == "" {
		hostname = "—"
	}
	if len(hostname) > 28 {
		hostname = hostname[:26] + "…"
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
	var portParts []string
	for _, p := range r.OpenPorts {
		portParts = append(portParts, fmt.Sprintf("%d", p))
	}
	portStr := "—"
	if len(portParts) > 0 {
		portStr = strings.Join(portParts, ",")
	}
	row := fmt.Sprintf(" %-16s  %-28s  %-17s  %-20s  %-8s  %-10s  %-12s",
		r.IP, hostname, mac, vendor, latency, osStr, portStr)
	var banners []string
	for _, bv := range []struct{ l, v string }{
		{"SSH", r.Banner.SSH}, {"HTTP", r.Banner.HTTP}, {"HTTPS", r.Banner.HTTPS},
		{"FTP", r.Banner.FTP}, {"SMTP", r.Banner.SMTP},
	} {
		if bv.v != "" {
			banners = append(banners, bv.l+":"+bv.v)
		}
	}
	if r.SNMP != nil && r.SNMP.SysDescr != "" {
		banners = append(banners, "SNMP:"+r.SNMP.SysDescr)
	}
	line := tuiStyleAlive.Render(row)
	if len(banners) > 0 {
		line += "  " + tuiStyleBanner.Render(strings.Join(banners, "  "))
	}
	return line
}

func tuiClamp(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

func runTUI() {
	cfg, cfgPath, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: %v\n", err)
	}
	if cfgPath != "" {
		fmt.Fprintf(os.Stderr, "config: %s\n", cfgPath)
	}

	fs := pflag.NewFlagSet("net-sweep", pflag.ContinueOnError)
	fs.SortFlags = false

	timeout     := fs.DurationP("timeout", "t", cfg.Scan.ParseTimeout(), "per-host probe timeout")
	concurrency := fs.IntP("concurrency", "c", cfg.Scan.Concurrency, "maximum concurrent probes")
	portsFlag   := fs.StringP("ports", "p", "", "comma-separated TCP ports (overrides config)")
	noPing      := fs.Bool("no-ping", !cfg.Scan.PingFirst, "skip ICMP pre-check")
	noSNMP      := fs.Bool("no-snmp", false, "disable SNMP probing")
	noBroadcast := fs.Bool("no-broadcast", false, "disable mDNS/SSDP discovery")
	noBanner    := fs.Bool("no-banner", false, "disable service banner grabbing")
	noNetBIOS   := fs.Bool("no-netbios", false, "disable NetBIOS name queries")
	showVersion := fs.BoolP("version", "V", false, "print version and exit")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: net-sweep --tui [OPTIONS] <target>\n\n")
		fmt.Fprintf(os.Stderr, "  <target>  single IP or CIDR (e.g. 192.168.1.0/24)\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		fs.Usage()
		os.Exit(2)
	}
	if *showVersion {
		fmt.Printf("net-sweep %s (tui)\n", version)
		os.Exit(0)
	}
	if fs.NArg() != 1 {
		fs.Usage()
		os.Exit(2)
	}
	target := fs.Arg(0)

	if *timeout < 50*time.Millisecond || *timeout > 5*time.Minute {
		fmt.Fprintln(os.Stderr, "error: --timeout must be between 50ms and 5m")
		os.Exit(2)
	}
	if *concurrency < 1 || *concurrency > 65535 {
		fmt.Fprintln(os.Stderr, "error: --concurrency must be between 1 and 65535")
		os.Exit(2)
	}

	hosts, err := sweep.ExpandTarget(target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	if !sweep.IsPrivate(target) {
		fmt.Fprintf(os.Stderr,
			"warning: target %q is not RFC1918/private. Proceed? [y/N] ", target)
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
	if *portsFlag != "" {
		scanCfg.Ports = cliParsePorts(*portsFlag)
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

	sigCtx, sigCancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer sigCancel()
	ctx, cancel := context.WithCancel(sigCtx)

	m := tuiModel{target: target, total: len(hosts), cancel: cancel}
	p := tea.NewProgram(m, tea.WithAltScreen())

	go func() {
		ch, err := sweep.NewScanner(scanCfg).Scan(ctx, target)
		if err != nil {
			p.Send(tuiErrMsg{err})
			return
		}
		for r := range ch {
			p.Send(tuiResultMsg(r))
		}
		p.Send(tuiDoneMsg{})
	}()

	if _, err := p.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}
