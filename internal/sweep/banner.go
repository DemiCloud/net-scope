package sweep

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

// BannerInfo holds service fingerprints grabbed from open ports.
type BannerInfo struct {
	HTTP  string // HTTP Server header (or title)
	HTTPS string // HTTPS Server header
	SSH   string // SSH version string (e.g. "OpenSSH_9.3")
	FTP   string // FTP greeting
	SMTP  string // SMTP greeting
	Telnet string // Telnet banner line
}

// grabBanners attempts lightweight banner grabs on well-known open ports and
// returns a BannerInfo. Only ports that are in openPorts are probed. It never
// opens a connection to a port that wasn't already confirmed open.
func grabBanners(ctx context.Context, ip net.IP, openPorts []int, timeout time.Duration, dial DialFunc) BannerInfo {
	portSet := make(map[int]bool, len(openPorts))
	for _, p := range openPorts {
		portSet[p] = true
	}

	var info BannerInfo

	type probe struct {
		port int
		fn   func()
	}

	probes := []probe{
		{22, func() {
			if portSet[22] {
				info.SSH = grabSSH(ctx, ip, timeout, dial)
			}
		}},
		{21, func() {
			if portSet[21] {
				info.FTP = grabLineBanner(ctx, ip, 21, timeout, dial)
			}
		}},
		{23, func() {
			if portSet[23] {
				info.Telnet = grabLineBanner(ctx, ip, 23, timeout, dial)
			}
		}},
		{25, func() {
			if portSet[25] {
				info.SMTP = grabLineBanner(ctx, ip, 25, timeout, dial)
			}
		}},
		{80, func() {
			if portSet[80] {
				info.HTTP = grabHTTP(ctx, ip, 80, false, timeout, dial)
			}
		}},
		{8080, func() {
			if portSet[8080] && info.HTTP == "" {
				info.HTTP = grabHTTP(ctx, ip, 8080, false, timeout, dial)
			}
		}},
		{443, func() {
			if portSet[443] {
				info.HTTPS = grabHTTP(ctx, ip, 443, true, timeout, dial)
			}
		}},
		{8443, func() {
			if portSet[8443] && info.HTTPS == "" {
				info.HTTPS = grabHTTP(ctx, ip, 8443, true, timeout, dial)
			}
		}},
	}

	for _, p := range probes {
		if ctx.Err() != nil {
			break
		}
		p.fn()
	}

	return info
}

// grabHTTP issues a HEAD (then GET on failure) to http(s)://ip:port/ and
// returns the Server header or page title.
func grabHTTP(ctx context.Context, ip net.IP, port int, tls_ bool, timeout time.Duration, dial DialFunc) string {
	scheme := "http"
	if tls_ {
		scheme = "https"
	}
	url := fmt.Sprintf("%s://%s/", scheme, net.JoinHostPort(ip.String(), fmt.Sprintf("%d", port)))

	transport := &http.Transport{
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // admin tool scanning own LAN
		DisableKeepAlives: true,
		DialContext:       dialOrDirect(dial),
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   timeout,
		// Don't follow redirects — we want the banner from the original host.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodHead, url, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("User-Agent", "net-scope/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	resp.Body.Close()

	// Prefer the Server header.
	if sv := resp.Header.Get("Server"); sv != "" {
		return sv
	}
	// Fall back to X-Powered-By.
	if xpb := resp.Header.Get("X-Powered-By"); xpb != "" {
		return xpb
	}
	return ""
}

// grabSSH connects to port 22 and reads the SSH identification string.
func grabSSH(ctx context.Context, ip net.IP, timeout time.Duration, dial DialFunc) string {
	dl := time.Now().Add(timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(dl) {
		dl = d
	}
	conn, err := dialOrDirect(dial)(ctx, "tcp", net.JoinHostPort(ip.String(), "22"))
	if err != nil {
		return ""
	}
	defer conn.Close()
	conn.SetDeadline(dl)

	scanner := bufio.NewScanner(conn)
	if scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// SSH-2.0-OpenSSH_9.3p2 → strip "SSH-2.0-" prefix
		if strings.HasPrefix(line, "SSH-") {
			parts := strings.SplitN(line, "-", 3)
			if len(parts) == 3 {
				return parts[2] // e.g. "OpenSSH_9.3p2 Ubuntu-1ubuntu3.3"
			}
			return line
		}
		return line
	}
	return ""
}

// grabLineBanner connects to port and reads the first non-empty line (FTP, SMTP, Telnet).
func grabLineBanner(ctx context.Context, ip net.IP, port int, timeout time.Duration, dial DialFunc) string {
	dl := time.Now().Add(timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(dl) {
		dl = d
	}
	conn, err := dialOrDirect(dial)(ctx, "tcp",
		net.JoinHostPort(ip.String(), fmt.Sprintf("%d", port)))
	if err != nil {
		return ""
	}
	defer conn.Close()
	conn.SetDeadline(dl)

	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			// Strip numeric response codes from FTP/SMTP (e.g. "220 " prefix)
			if len(line) > 4 && line[3] == ' ' {
				if line[0] >= '0' && line[0] <= '9' {
					line = strings.TrimSpace(line[4:])
				}
			}
			// Limit to 120 chars to keep display sane
			if len(line) > 120 {
				line = line[:120]
			}
			return line
		}
	}
	return ""
}
