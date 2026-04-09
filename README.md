# net-scope

A LAN network inspection and reconnaissance tool combining active probing, passive signal
analysis, and change detection for IPv4 networks. Produces a single binary per platform
with CLI, TUI, and GUI front-ends.

## Features

- **Host discovery** — ARP (batch), ICMP fallback, TCP liveness fallback
- **Port scanning** — TCP connect on a configurable port list
- **Service banner grabbing** — SSH, HTTP/HTTPS (with TLS cert info), FTP, SMTP, Telnet
- **OS fingerprinting** — multi-signal voting: SNMP → OUI → SSH banner → HTTP header → mDNS/SSDP → TCP SYN window size → ICMP TTL
- **Passive broadcast discovery** — mDNS (Zeroconf), SSDP (UPnP), WS-Discovery (WSD)
- **SNMP v2c** — queries sysDescr, sysName, sysLocation, sysContact
- **NetBIOS** name queries (UDP 137)
- **DHCP passive capture** — promiscuous raw socket capture (Windows, elevation required)
- **SOCKS5 proxy mode** — route all TCP through a proxy; disables ARP/ICMP/mDNS/SSDP/WSD/SNMP
- **OUI vendor lookup** — embedded MAC vendor database (`with_oui` build tag)
- **ARP anomaly detection** — cross-references batch ARP with the kernel ARP cache
- **Export** — JSON and CSV

---

## Installation

**Pre-built binaries** are attached to each GitHub release under `dist/`.

| File | Platform |
| ------ | ---------- |
| `net-scope_linux_amd64.tar.gz` | Linux x86-64 (static, no dependencies) |
| `net-scope_linux_arm64.tar.gz` | Linux ARM64 (static, no dependencies) |
| `net-scope_windows_amd64.zip` | Windows x86-64 |
| `net-scope_freebsd_amd64.tar.gz` | FreeBSD x86-64 (static, no dependencies) |

A `checksums.txt` (SHA-256) is included in each release.

---

## Quick Start

```bash
# Scan a subnet — auto-selects platform default (CLI on Linux, GUI on Windows double-click)
net-scope 192.168.1.0/24

# Force CLI mode
net-scope cli 192.168.1.0/24

# Interactive TUI (Linux/BSD)
net-scope tui 192.168.1.0/24

# Faster scan: shorter timeout, more workers
net-scope cli -t 500ms -c 512 192.168.1.0/24

# Export JSON to a file
net-scope cli -f json -o results.json 192.168.1.0/24

# Route all TCP through a SOCKS5 proxy
net-scope cli --socks 127.0.0.1:1080 10.0.0.0/8
```

---

## Subcommands

```text
net-scope cli    [target] [flags]   # Plain-text output — all platforms
net-scope tui    [target] [flags]   # Bubbletea TUI — Linux/BSD only
net-scope gui    [target]           # Win32 GUI (Windows) or GTK3 GUI (Linux GUI build)
net-scope service <addr> <token>    # Internal: sensor service subprocess (spawned by GUI)
```

Running with **no subcommand** picks the platform default:

| Platform | Default |
| ---------- | --------- |
| Windows (terminal / AttachConsole) | `cli` |
| Windows (double-click, no parent console) | `gui` |
| Linux static build | `cli` (override with `default_mode = "tui"` in config) |
| Linux GUI build | `cli` (override with `default_mode = "gui"` or `"tui"`) |
| FreeBSD / BSD | `cli` |

---

## CLI Flags

```text
net-scope cli [flags] <target>
```

`target` is a single IPv4 address (`10.0.0.1`) or CIDR range (`192.168.1.0/24`).
Non-private targets prompt for confirmation.

| Flag | Short | Default | Description |
| ------ | ------- | --------- | ------------- |
| `--timeout` | `-t` | `1s` | Per-host probe timeout (50 ms – 5 m) |
| `--concurrency` | `-c` | `256` | Max concurrent probes (1 – 65535) |
| `--format` | `-f` | `text` | Output format: `text`, `json`, `csv` |
| `--output` | `-o` | *(stdout)* | Write output to file |
| `--ports` | `-p` | *(config)* | Comma-separated TCP ports to scan |
| `--interface` | `-i` | *(auto)* | NIC for ARP (e.g. `eth0`) |
| `--snmp-community` | | `public` | SNMP v2c community string |
| `--socks` | | | SOCKS5 proxy `host:port` |
| `--no-ping` | | | Scan all IPs without ICMP pre-check |
| `--no-snmp` | | | Disable SNMP probing |
| `--no-broadcast` | | | Disable mDNS / SSDP discovery |
| `--no-banner` | | | Disable service banner grabbing |
| `--no-netbios` | | | Disable NetBIOS name queries |
| `--show-down` | | | Include non-responding hosts in output |
| `--version` | `-V` | | Print version and exit |

---

## Configuration

Config file is loaded from (in order of precedence):

1. Platform user config directory:
   - **Windows:** `%APPDATA%\demicloud\net-scope\config.toml`
   - **Linux / BSD:** `~/.config/demicloud/net-scope/config.toml`
2. `./config.toml` (current working directory — useful for per-project CLI overrides)

If no file exists, built-in defaults are used silently. The file is **not** created
automatically — the GUI prompts on first save.

### All Options

```toml
# Platform default when no subcommand is given.
# Values: "cli", "tui", "gui", or "" (platform auto-select)
default_mode = ""

[scan]
timeout          = "1s"     # Per-host probe timeout (Go duration string)
concurrency      = 256      # Max concurrent probes
ports            = [21, 22, 23, 25, 80, 443, 445, 3389, 8080, 8443]
ping_first       = true     # ICMP liveness check before TCP port scan
broadcast_listen = "3s"     # mDNS + SSDP listen window; "0s" disables
snmp_community   = "public" # SNMP v2c community string; "" disables SNMP
interface        = ""       # NIC for ARP; "" = auto-detect
banner_grab      = true     # Grab SSH / HTTP / FTP / SMTP / Telnet banners
netbios          = true     # NetBIOS name queries (UDP 137)
socks_proxy      = ""       # SOCKS5 proxy "host:port"
default_target   = ""       # Pre-fill GUI target box on startup

# Custom protocol handlers — %s is replaced with the host IP
[scan.protocol_handlers]
# http   = "firefox http://%s"
# https  = "firefox https://%s"
# ssh    = "putty.exe -ssh %s"
# rdp    = "mstsc.exe /v:%s"
# ftp    = ""
# telnet = ""
# smb    = ""
```

---

## Output Formats

### `text` (default)

Fixed-width, ANSI-coloured when writing to a TTY:

```text
IP               Hostname / NetBIOS             MAC                Vendor               Latency   OS            Ports         Banners / SNMP
192.168.1.1      router.local                   aa:bb:cc:dd:ee:ff  Cisco Systems         2ms       RouterOS      22,80,443     SSH: ROSSSH  HTTP: Apache/2.4
  └ [mdns] My Printer (_ipp._tcp)
```

Progress is printed to stderr: `[45%]  45/100 probed  12 alive`

Pass `--show-down` to show non-responding hosts (greyed out).

### `json`

Pretty-printed JSON array. Example object:

```json
{
  "ip": "192.168.1.1",
  "alive": true,
  "mac": "aa:bb:cc:dd:ee:ff",
  "vendor": "Cisco Systems",
  "hostname": "router.local",
  "os": "RouterOS",
  "open_ports": [22, 80, 443],
  "latency_ms": 2,
  "ttl": 64,
  "banner": { "ssh": "ROSSSH", "http": "Apache/2.4" },
  "snmp": { "sys_name": "router", "sys_descr": "Linux 5.15" },
  "services": [{ "source": "mdns", "name": "My Printer", "type": "_ipp._tcp", "details": "..." }]
}
```

### `csv`

RFC 4180 CSV with a header row. Columns:

```text
ip, alive, mac, vendor, hostname, netbios, os, open_ports, latency_ms, ttl,
banner_ssh, banner_http, banner_https, banner_ftp, banner_smtp, banner_telnet,
snmp_descr, snmp_name, snmp_location, snmp_contact, services
```

`open_ports` is semicolon-separated. `services` entries are `[source] name (type)` joined by `"; "`.

---

## OS Detection

OS guesses are produced by a confidence-weighted voting system:

| Source | Weight | Examples |
| ------ | ------ | --------- |
| SNMP sysDescr | 90 | Self-reported OS string |
| Proprietary SSH banner | 90 | `SSH-2.0-ROSSSH` → RouterOS |
| Specific SSH banner | 85 | Mentions distro or vendor |
| HTTP vendor header | 75 | `Microsoft-IIS`, `HTTPAPI` |
| MAC OUI | 75 | Apple → macOS, Cisco → Cisco IOS |
| mDNS / SSDP service type | 65 | `_airplay._tcp` → macOS |
| TCP SYN window size | 55 | OS-specific initial window |
| Generic HTTP banner | 50 | Apache / nginx (can run anywhere) |
| Generic SSH presence | 40 | SSH open, no other signal → Linux |
| ICMP TTL heuristic | 30 | TTL ≈ 128 → Windows, ≈ 64 → Linux |

Possible reported values: `Windows`, `Linux`, `macOS`, `Network Device`, `RouterOS`,
`Cisco IOS`, `JunOS`, `Ubiquiti`, `Aruba`, `Fortinet`.

---

## Elevation & Raw Sockets

Some features require elevated privileges:

| Feature | Linux | Windows |
| --------- | ------- | --------- |
| ARP batch scan | CAP_NET_RAW | Standard user |
| ICMP liveness | CAP_NET_RAW | Standard user |
| TCP SYN probe | CAP_NET_RAW | Standard user |
| DHCP passive capture | Not available | Elevated service (UAC prompt) |

On Linux, grant the binary the necessary capability instead of running as root:

```bash
sudo setcap cap_net_raw+ep ./net-scope
```

On Windows, the GUI can relaunch its sensor subprocess with UAC elevation to unlock
DHCP capture. The main GUI window itself does not need elevation.

---

## SOCKS5 Proxy Mode

```bash
net-scope cli --socks 127.0.0.1:1080 10.10.0.0/16
```

When a proxy is configured all TCP connections (port scans and banner grabs) are routed
through it. Protocols that cannot be proxied — ARP, ICMP, mDNS, SSDP, WS-Discovery,
NetBIOS UDP, SNMP UDP — are automatically disabled.

---

## Platform Support

| Feature | Windows | Linux (static) | Linux (GUI build) | FreeBSD |
| --------- | --------- | --------------- | ------------------- | --------- |
| CLI | ✓ | ✓ | ✓ | ✓ |
| TUI | — | ✓ | ✓ | ✓ |
| GUI | ✓ Win32 | — | ✓ GTK3 | — |
| DHCP capture | ✓ (elevated) | — | ✓ (elevated) | — |
| ARP scan | ✓ | ✓ | ✓ | ✓ |
| TCP SYN probe | ✓ | ✓ (CAP_NET_RAW) | ✓ (CAP_NET_RAW) | ✓ (CAP_NET_RAW) |
| mDNS / SSDP / WSD | ✓ | ✓ | ✓ | ✓ |

---

## Building from Source

**Requirements:**

- Go 1.25+
- Linux / WSL for cross-compilation
- `gcc`, `libgtk-3-dev`, `libglib2.0-dev` (or `gtk3-devel glib2-devel` on Fedora) for the Linux GUI build only

```bash
# Clone
git clone https://github.com/demicloud/net-scope.git
cd net-scope

# Development builds
make linux           # Static Linux binary (CLI + TUI)
make linux-gui       # Linux binary with GTK3 GUI (requires CGo + GTK3 dev libs)
make windows         # Windows binary (cross-compiled from Linux)
make bsd             # FreeBSD binary

# All static platforms at once
make all

# Stripped release builds → dist/
make release

# Tests and vet
make test
make vet
```

Build tags used internally:

| Tag | Effect |
| --- | ------ |
| `with_oui` | Embeds `oui.json` for MAC vendor lookup (applied by all Makefile targets) |
| `gui` | Includes GTK3 GUI package (Linux GUI build only) |

Version is injected at link time from `git describe`:

```bash
-ldflags "-X main.version=$(git describe --tags --always --dirty)"
```

---

## Architecture

```text
cmd/net-scope/       Unified entry point; dispatches to CLI, TUI, or GUI
cmd/gui-win/         Win32 GUI (Windows only; primary graphical target; no CGo)
cmd/gui-gtk/         GTK3 GUI (Linux only; requires CGo; build tag: linux,gui)
internal/scan/       All network I/O, scanning, enrichment, result types, wire protocol
internal/config/     TOML config; Load() / SaveTo()
```

**Key design rules:**

- All network I/O goes through `internal/scan/`. The GUI never calls scan functions or
  opens sockets directly.
- The GUI spawns itself as a `service` subprocess. The parent generates an ephemeral
  ECDSA P-256 TLS certificate and passes its SHA-256 fingerprint on the command line.
  Communication is newline-delimited JSON over a TLS 1.3 loopback connection.
- The service IPC client (`cmd/gui-win/service.go`) has zero GUI imports — it can be
  reused by any front-end.
- No CGo on Windows, Linux static, or FreeBSD. Win32 accessed entirely via
  `syscall.NewLazyDLL`.

---

## License

See [LICENSE](https://github.com/demicloud/net-scope/blob/main/LICENSE).
