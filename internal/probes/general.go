package probes

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"github.com/demicloud/net-scope/internal/scan"
)

func registerGeneral() {
	scan.RegisterDeepProbe(scan.DeepProbe{
		ID:          "tcp",
		Group:       "General",
		Name:        "TCP Connect",
		DefaultPort: 80,
		Transport:   "TCP",
		Run:         probeTCPConnect,
	})
	scan.RegisterDeepProbe(scan.DeepProbe{
		ID:          "tls",
		Group:       "General",
		Name:        "TLS Handshake",
		DefaultPort: 443,
		Transport:   "TCP",
		Run:         probeTLSHandshake,
	})
}

// probeTCPConnect checks whether a TCP port is open and how quickly it responds.
func probeTCPConnect(_ context.Context, ip string, port int, dial scan.DialFunc, emit func(string)) ([]scan.Observation, error) {
	emit(fmt.Sprintf("Connecting to %s (TCP)…", joinHost(ip, port)))
	start := time.Now()
	conn, err := dialTCP(context.Background(), dial, ip, port, 5*time.Second)
	if err != nil {
		s := err.Error()
		switch {
		case isRefused(s):
			emit("Connection refused — port is closed or filtered")
		case isTimeout(s):
			emit("Connection timed out — host is unreachable or port is firewalled")
		default:
			emit("Error: " + s)
		}
		return []scan.Observation{obs("probe", "status", "closed")}, nil
	}
	conn.Close()
	rtt := time.Since(start).Round(time.Millisecond)
	emit(fmt.Sprintf("Port %d is open  (RTT %s)", port, rtt))
	return []scan.Observation{
		obs("probe", "status", "open"),
		obs("probe", "rtt", rtt.String()),
	}, nil
}

// probeTLSHandshake performs a TLS handshake and reports certificate details.
func probeTLSHandshake(_ context.Context, ip string, port int, dial scan.DialFunc, emit func(string)) ([]scan.Observation, error) {
	emit(fmt.Sprintf("Connecting to %s (TLS)…", joinHost(ip, port)))
	tc, err := dialTCP(context.Background(), dial, ip, port, 5*time.Second)
	if err != nil {
		emit("Connection failed: " + err.Error())
		return nil, nil
	}
	defer tc.Close()

	emit("Performing TLS handshake…")
	tlsConn := tls.Client(tc, &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // intentional: we report cert details, not verify
		ServerName:         ip,
	})
	tlsConn.SetDeadline(time.Now().Add(5 * time.Second)) //nolint:errcheck
	if err := tlsConn.Handshake(); err != nil {
		emit("TLS handshake failed: " + err.Error())
		return nil, nil
	}

	state := tlsConn.ConnectionState()
	var version string
	switch state.Version {
	case tls.VersionTLS10:
		version = "TLS 1.0 (obsolete)"
	case tls.VersionTLS11:
		version = "TLS 1.1 (obsolete)"
	case tls.VersionTLS12:
		version = "TLS 1.2"
	case tls.VersionTLS13:
		version = "TLS 1.3"
	default:
		version = fmt.Sprintf("TLS 0x%04X", state.Version)
	}
	emit("Protocol: " + version)

	var result []scan.Observation
	result = append(result, obs("probe", "tls_version", version))

	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		cn := cert.Subject.CommonName
		issuer := ""
		if len(cert.Issuer.Organization) > 0 {
			issuer = cert.Issuer.Organization[0]
		} else {
			issuer = cert.Issuer.CommonName
		}
		emit(fmt.Sprintf("Subject: %s", cn))
		emit(fmt.Sprintf("Issuer:  %s", issuer))
		expires := cert.NotAfter.Format("2006-01-02")
		now := time.Now()
		if cert.NotAfter.Before(now) {
			emit("⚠  Certificate EXPIRED on " + expires)
		} else {
			emit("Expires: " + expires)
		}
		// SANs
		var sans []string
		sans = append(sans, cert.DNSNames...)
		for _, ip := range cert.IPAddresses {
			sans = append(sans, ip.String())
		}
		if len(sans) > 0 {
			sanStr := joinStrings(sans, ", ")
			emit("SANs:    " + sanStr)
			result = append(result, obs("probe", "tls_sans", sanStr))
		}
		selfSigned := cert.Issuer.CommonName == cert.Subject.CommonName
		if selfSigned {
			emit("⚠  Self-signed certificate")
		}
		result = append(result, obs("probe", "tls_subject", cn))
		result = append(result, obs("probe", "tls_issuer", issuer))
		result = append(result, obs("probe", "tls_expires", expires))
	}
	// Cipher suite
	suite := tls.CipherSuiteName(state.CipherSuite)
	emit("Cipher:  " + suite)
	result = append(result, obs("probe", "tls_cipher", suite))

	// ALPN negotiated protocol
	if state.NegotiatedProtocol != "" {
		emit("ALPN:    " + state.NegotiatedProtocol)
		result = append(result, obs("probe", "alpn", state.NegotiatedProtocol))
	}
	return result, nil
}

// ---------------------------------------------------------------------------
// Utility helpers used across multiple probe files
// ---------------------------------------------------------------------------

func isRefused(s string) bool {
	return containsAny(s, "refused", "actively refused", "connection refused")
}

func isTimeout(s string) bool {
	return containsAny(s, "timeout", "timed out", "i/o timeout")
}

func containsAny(s string, subs ...string) bool {
	sl := toLower(s)
	for _, sub := range subs {
		if containsStr(sl, sub) {
			return true
		}
	}
	return false
}

func toLower(s string) string {
	b := make([]byte, len(s))
	for i := range s {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 32
		}
		b[i] = c
	}
	return string(b)
}

func containsStr(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(s) > 0 && findStr(s, sub))
}

func findStr(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func joinStrings(ss []string, sep string) string {
	if len(ss) == 0 {
		return ""
	}
	out := ss[0]
	for _, s := range ss[1:] {
		out += sep + s
	}
	return out
}

// netIP converts an ip string to net.IP (IPv4 canonical form).
func netIP(ip string) net.IP {
	p := net.ParseIP(ip)
	if p == nil {
		return nil
	}
	if p4 := p.To4(); p4 != nil {
		return p4
	}
	return p
}
