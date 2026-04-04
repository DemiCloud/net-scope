// Package config loads and persists net-sweep settings from a TOML file.
//
// Search order:
//  1. ./config.toml          (current directory — good for CLI per-project use)
//  2. <userConfigDir>/net-sweep/config.toml
//     Linux:   ~/.config/net-sweep/config.toml
//     Windows: %APPDATA%\net-sweep\config.toml
//
// If no file is found, built-in defaults are used and a starter file is written
// to the user config directory.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/demicloud/net-sweep/internal/sweep"
)

// File is the config filename looked for in each search location.
const File = "config.toml"

// Config is the top-level structure that maps to the TOML file.
type Config struct {
	Scan ScanConfig `toml:"scan"`
}

// ScanConfig holds all tunable scan parameters.
type ScanConfig struct {
	// Timeout is a Go duration string, e.g. "1s", "500ms".
	Timeout string `toml:"timeout"`

	Concurrency int `toml:"concurrency"`

	// Ports scanned via TCP connect on every alive host.
	Ports []int `toml:"ports"`

	// PingFirst skips TCP scan on hosts that don't respond to ICMP.
	PingFirst bool `toml:"ping_first"`

	// BroadcastListen is how long to listen for mDNS/SSDP traffic.
	// Set to "0s" to disable broadcast discovery entirely.
	BroadcastListen string `toml:"broadcast_listen"`

	// SNMPCommunity is the SNMP v2c community string.
	// Leave empty to disable SNMP probing.
	SNMPCommunity string `toml:"snmp_community"`

	// Interface name to use for ARP scanning, e.g. "eth0".
	// Leave empty to auto-detect from routing table.
	Interface string `toml:"interface"`
}

// Default returns the built-in defaults. Used when no config file exists
// and as a baseline before merging a loaded file.
func Default() Config {
	return Config{
		Scan: ScanConfig{
			Timeout:     "1s",
			Concurrency: 256,
			Ports: []int{
				21,   // FTP
				22,   // SSH
				23,   // Telnet
				80,   // HTTP
				443,  // HTTPS
				445,  // SMB
				3389, // RDP
				8080, // HTTP-alt
				8443, // HTTPS-alt
			},
			PingFirst:       true,
			BroadcastListen: "3s",
			SNMPCommunity:   "public",
		},
	}
}

// Load searches for a config file and returns the merged result.
// Missing files are not an error — defaults are returned instead.
func Load() (Config, string, error) {
	candidates := searchPaths()
	for _, p := range candidates {
		cfg, err := loadFile(p)
		if err == nil {
			return cfg, p, nil
		}
		if !os.IsNotExist(err) {
			return Default(), "", fmt.Errorf("config: parse error in %s: %w", p, err)
		}
	}

	// No file found — write a starter to the user config dir and use defaults.
	cfg := Default()
	if dir, err := userConfigPath(); err == nil {
		_ = writeDefault(dir)
	}
	return cfg, "", nil
}

// ToSweepConfig converts the TOML config into a sweep.Config.
func (c Config) ToSweepConfig() sweep.Config {
	timeout := parseDurationOr(c.Scan.Timeout, time.Second)
	bl := parseDurationOr(c.Scan.BroadcastListen, 3*time.Second)

	return sweep.Config{
		Timeout:         timeout,
		Concurrency:     c.Scan.Concurrency,
		Ports:           c.Scan.Ports,
		PingFirst:       c.Scan.PingFirst,
		BroadcastListen: bl,
		SNMPCommunity:   c.Scan.SNMPCommunity,
		Interface:       c.Scan.Interface,
	}
}

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

func searchPaths() []string {
	paths := []string{"config.toml"}
	if p, err := userConfigPath(); err == nil {
		paths = append(paths, p)
	}
	return paths
}

func userConfigPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "net-sweep", File), nil
}

func loadFile(path string) (Config, error) {
	cfg := Default()
	_, err := toml.DecodeFile(path, &cfg)
	return cfg, err
}

func writeDefault(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = fmt.Fprint(f, defaultTOML)
	return err
}

// Save writes cfg to the user config directory as TOML.
// The file is created if it does not exist; an existing file is overwritten.
func Save(cfg Config) error {
	p, err := userConfigPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
		return err
	}
	f, err := os.Create(p)
	if err != nil {
		return err
	}
	defer f.Close()
	return toml.NewEncoder(f).Encode(cfg)
}

// ConfigPath returns the expected user-level config file path.
// The file may not exist yet; calling Load() will create it with defaults.
func ConfigPath() string {
	p, err := userConfigPath()
	if err != nil {
		return ""
	}
	return p
}

// ParseTimeout parses the Timeout string, returning 1s on error.
func (s ScanConfig) ParseTimeout() time.Duration {
	return parseDurationOr(s.Timeout, time.Second)
}

func parseDurationOr(s string, fallback time.Duration) time.Duration {
	if d, err := time.ParseDuration(s); err == nil {
		return d
	}
	return fallback
}

// defaultTOML is the starter file written on first run.
const defaultTOML = `# net-sweep configuration
# All durations use Go syntax: "1s", "500ms", "2m", etc.

[scan]
# Per-host probe timeout.
timeout = "1s"

# Maximum concurrent host probes.
concurrency = 256

# TCP ports to scan on every alive host.
ports = [21, 22, 23, 80, 443, 445, 3389, 8080, 8443]

# Skip TCP scan on hosts that don't respond to ICMP ping.
ping_first = true

# How long to listen for mDNS/SSDP broadcast traffic.
# Set to "0s" to disable.
broadcast_listen = "3s"

# SNMP v2c community string. Empty string disables SNMP.
snmp_community = "public"

# Network interface for ARP scanning (e.g. "eth0", "Ethernet").
# Leave empty to auto-detect from the target subnet.
interface = ""
`
