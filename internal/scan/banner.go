package scan

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
	"unicode"
)

// BannerInfo holds service fingerprints grabbed from open ports.
type BannerInfo struct {
	HTTP    string // HTTP Server header (or title)
	HTTPS   string // HTTPS Server header
	TLSCert string // TLS certificate subject + issuer, e.g. "smartcast.vizio.com (Vizio)"
	SSH     string // SSH version string (e.g. "OpenSSH_9.3")
	FTP     string // FTP greeting
	SMTP    string // SMTP greeting
	Telnet  string // Telnet banner line
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
		// 8080: try plain HTTP first; fall back to HTTPS (some IoT devices serve
		// TLS on 8080 regardless of convention).
		{8080, func() {
			if !portSet[8080] {
				return
			}
			if info.HTTP == "" {
				info.HTTP = grabHTTP(ctx, ip, 8080, false, timeout, dial)
			}
			if info.HTTP == "" {
				info.HTTPS = grabHTTP(ctx, ip, 8080, true, timeout, dial)
				if info.TLSCert == "" {
					info.TLSCert = grabTLSCert(ctx, ip, 8080, timeout, dial)
				}
			}
		}},
		{443, func() {
			if !portSet[443] {
				return
			}
			if info.HTTPS == "" {
				info.HTTPS = grabHTTP(ctx, ip, 443, true, timeout, dial)
			}
			if info.TLSCert == "" {
				info.TLSCert = grabTLSCert(ctx, ip, 443, timeout, dial)
			}
			// Some devices serve plain HTTP on 443 (misconfigured but real).
			if info.HTTPS == "" && info.TLSCert == "" {
				info.HTTP = grabHTTP(ctx, ip, 443, false, timeout, dial)
			}
		}},
		// 8443: try HTTPS first; grab TLS cert regardless of Server header;
		// fall back to plain HTTP if TLS fails entirely.
		{8443, func() {
			if !portSet[8443] {
				return
			}
			if info.HTTPS == "" {
				info.HTTPS = grabHTTP(ctx, ip, 8443, true, timeout, dial)
			}
			if info.TLSCert == "" {
				info.TLSCert = grabTLSCert(ctx, ip, 8443, timeout, dial)
			}
			if info.HTTPS == "" && info.TLSCert == "" {
				info.HTTP = grabHTTP(ctx, ip, 8443, false, timeout, dial)
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

// grabTLSInfo performs a TLS handshake and returns the peer certificate
// descriptor ("SubjectCN (IssuerOrg)") and the negotiated ALPN protocol
// (e.g. "h2", "http/1.1"). Either value may be empty on failure or when the
// server does not advertise that information.
func grabTLSInfo(ctx context.Context, ip net.IP, port int, timeout time.Duration, dial DialFunc) (cert, alpn string) {
	addr := net.JoinHostPort(ip.String(), fmt.Sprintf("%d", port))
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	raw, err := dialOrDirect(dial)(reqCtx, "tcp", addr)
	if err != nil {
		return "", ""
	}
	defer raw.Close()
	raw.SetDeadline(time.Now().Add(timeout)) //nolint:errcheck

	tlsConn := tls.Client(raw, &tls.Config{ //nolint:gosec // admin LAN scanner
		InsecureSkipVerify: true,
		ServerName:         ip.String(),
		NextProtos:         []string{"h2", "http/1.1"},
	})
	if err := tlsConn.Handshake(); err != nil {
		return "", ""
	}

	state := tlsConn.ConnectionState()
	alpn = state.NegotiatedProtocol

	certs := state.PeerCertificates
	if len(certs) == 0 {
		return "", alpn
	}
	leaf := certs[0]

	subject := leaf.Subject.CommonName
	issuer := ""
	if len(leaf.Issuer.Organization) > 0 {
		issuer = strings.Join(leaf.Issuer.Organization, ", ")
	} else if leaf.Issuer.CommonName != "" && leaf.Issuer.CommonName != subject {
		issuer = leaf.Issuer.CommonName
	}

	if len(leaf.DNSNames) > 0 && (subject == "" || !strings.ContainsAny(subject, ".")) {
		subject = strings.Join(leaf.DNSNames, ", ")
	}

	subject = cleanASCII(subject)
	issuer = cleanASCII(issuer)

	if subject != "" && issuer != "" && issuer != subject {
		cert = subject + " (" + issuer + ")"
	} else if subject != "" {
		cert = subject
	} else {
		cert = issuer
	}
	return cert, alpn
}

// grabTLSCert performs a TLS handshake to ip:port and returns a short
// descriptor of the peer certificate: "SubjectCN (IssuerOrg)" when both are
// present, otherwise whichever is available, or "" on failure.
// Useful for fingerprinting devices whose Server: header is empty or absent.
func grabTLSCert(ctx context.Context, ip net.IP, port int, timeout time.Duration, dial DialFunc) string {
	cert, _ := grabTLSInfo(ctx, ip, port, timeout, dial)
	return cert
}

// cleanASCII removes non-printable runes and trims whitespace.
func cleanASCII(s string) string {
	return strings.TrimSpace(strings.Map(func(r rune) rune {
		if r > 0x1F && r < 0x7F || r > 0xA0 && unicode.IsPrint(r) {
			return r
		}
		return -1
	}, s))
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

// portSignals holds the raw signals gathered from probing a single open port.
// It is an internal type used to pipeline signal collection before calling
// guessService for product identification.
type portSignals struct {
	port         int
	banner       string            // SSH ident / FTP greeting / SMTP / Telnet / RDP result
	serverHeader string            // HTTP Server: (or X-Powered-By) header value
	tlsCert      string            // TLS cert descriptor ("SubjectCN (IssuerOrg)")
	alpn         string            // TLS ALPN negotiated protocol ("h2", "http/1.1")
	details      map[string]string // protocol-specific key/value data (SMB, DNS, LDAP, MQTT)
}

// probePort gathers all available signals from a single confirmed-open TCP
// port. The port must already be known open; probePort will not attempt a
// TCP connect liveness check.
func probePort(ctx context.Context, ip net.IP, port int, timeout time.Duration, dial DialFunc) portSignals {
	sig := portSignals{port: port}

	switch port {
	case 22:
		sig.banner = grabSSH(ctx, ip, timeout, dial)

	case 21, 23:
		sig.banner = grabLineBanner(ctx, ip, port, timeout, dial)

	case 25, 587:
		sig.banner = grabLineBanner(ctx, ip, port, timeout, dial)

	case 465, 993, 995:
		// TLS-wrapped mail protocols: capture cert/ALPN, then try a banner read.
		sig.tlsCert, sig.alpn = grabTLSInfo(ctx, ip, port, timeout, dial)
		sig.banner = grabLineBanner(ctx, ip, port, timeout, dial)

	case 80, 8000, 8080, 8888:
		// Plain HTTP ports: try plain first, fall back to TLS.
		sig.serverHeader = grabHTTP(ctx, ip, port, false, timeout, dial)
		if sig.serverHeader == "" {
			sig.serverHeader = grabHTTP(ctx, ip, port, true, timeout, dial)
			if sig.serverHeader != "" {
				sig.tlsCert, sig.alpn = grabTLSInfo(ctx, ip, port, timeout, dial)
			}
		}

	case 443, 4443, 8443:
		// TLS-first ports: capture cert+ALPN, then HTTP header over TLS.
		sig.tlsCert, sig.alpn = grabTLSInfo(ctx, ip, port, timeout, dial)
		sig.serverHeader = grabHTTP(ctx, ip, port, true, timeout, dial)
		if sig.serverHeader == "" {
			// Some devices serve plain HTTP on 443 (misconfigured but real).
			sig.serverHeader = grabHTTP(ctx, ip, port, false, timeout, dial)
		}

	case 53:
		// DNS: custom binary probe for recursion and server identification.
		if dial == nil {
			sig.details = probeDNSPort(ctx, ip, timeout, dial)
		}

	case 389, 3268:
		// LDAP / LDAP Global Catalog: RootDSE query.
		if d := probeLDAP(ctx, ip, port, timeout, dial); d != nil {
			sig.details = d
		}

	case 445:
		// SMB: negotiate dialect and probe SMBv1 enablement.
		if d := probeSMB(ctx, ip, port, timeout, dial); d != nil {
			sig.details = d
			sig.banner = d["smb_dialect"]
		}

	case 1883, 8883:
		// MQTT broker: test unauthenticated access.
		if d := probeMQTT(ctx, ip, port, timeout, dial); d != nil {
			sig.details = d
		}

	case 3389:
		sig.banner = probeRDP(ctx, ip, port, timeout, dial)

	default:
		// Unknown port: try TLS first to see if it speaks HTTPS; then
		// attempt a plain HTTP HEAD; finally fall back to a raw line read.
		sig.tlsCert, sig.alpn = grabTLSInfo(ctx, ip, port, timeout, dial)
		if sig.tlsCert != "" || sig.alpn != "" {
			sig.serverHeader = grabHTTP(ctx, ip, port, true, timeout, dial)
		} else {
			sig.serverHeader = grabHTTP(ctx, ip, port, false, timeout, dial)
			if sig.serverHeader == "" {
				sig.banner = grabLineBanner(ctx, ip, port, timeout, dial)
			}
		}
	}

	return sig
}

// grabPortServices concurrently probes every port in openPorts and returns a
// slice of PortService values in the same order. Each entry carries the raw
// banner, server header, TLS certificate, and ALPN negotiated by that port,
// as well as the product/version identification from guessService.
//
// Only ports already confirmed open should be passed — probePort does not
// re-check liveness.
func grabPortServices(ctx context.Context, ip net.IP, openPorts []int, timeout time.Duration, dial DialFunc) []PortService {
	if len(openPorts) == 0 {
		return nil
	}

	type item struct {
		idx int
		svc PortService
	}
	ch := make(chan item, len(openPorts))

	var wg sync.WaitGroup
	for i, port := range openPorts {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		go func(idx, p int) {
			defer wg.Done()
			sig := probePort(ctx, ip, p, timeout, dial)

			product, version, conf := guessService(p, sig.banner, sig.serverHeader, sig.tlsCert, sig.alpn, sig.details)

			// Banner field in PortService holds whatever text we captured:
			// the server header for HTTP ports, the raw line banner for others.
			displayBanner := sig.serverHeader
			if displayBanner == "" {
				displayBanner = sig.banner
			}

			ch <- item{idx, PortService{
				Port:       p,
				Product:    product,
				Version:    version,
				Banner:     displayBanner,
				TLSCert:    sig.tlsCert,
				ALPN:       sig.alpn,
				Confidence: conf,
				Details:    sig.details,
			}}
		}(i, port)
	}

	go func() {
		wg.Wait()
		close(ch)
	}()

	svcs := make([]PortService, len(openPorts))
	for it := range ch {
		svcs[it.idx] = it.svc
	}
	return svcs
}

// bannerInfoFrom derives a BannerInfo from a slice of PortService values.
// This keeps all legacy consumers of BannerInfo (guessOS, WriteJSON, CLI
// output) working without changes after the transition to grabPortServices.
func bannerInfoFrom(svcs []PortService) BannerInfo {
	var b BannerInfo
	for _, s := range svcs {
		switch s.Port {
		case 22:
			if b.SSH == "" {
				b.SSH = s.Banner
			}
		case 21:
			if b.FTP == "" {
				b.FTP = s.Banner
			}
		case 23:
			if b.Telnet == "" {
				b.Telnet = s.Banner
			}
		case 25, 587:
			if b.SMTP == "" {
				b.SMTP = s.Banner
			}
		}
		if (s.Port == 80 || s.Port == 8080 || s.Port == 8000 || s.Port == 8888) && b.HTTP == "" {
			b.HTTP = s.Banner
		}
		if (s.Port == 443 || s.Port == 8443 || s.Port == 4443) && b.HTTPS == "" {
			b.HTTPS = s.Banner
		}
		// First TLS cert found wins; covers non-standard HTTPS ports too.
		if b.TLSCert == "" && s.TLSCert != "" {
			b.TLSCert = s.TLSCert
		}
	}
	return b
}
