package probes

import (
	"context"
	"crypto/tls"
	"fmt"
	"time"

	"github.com/demicloud/net-scope/internal/scan"
)

func registerWeb() {
	scan.RegisterDeepProbe(scan.DeepProbe{
		ID: "http", Group: "Web", Name: "HTTP [Banner]",
		ServiceName: "Web Server",
		DefaultPort: 80, Transport: "TCP", Run: probeHTTP,
	})
	scan.RegisterDeepProbe(scan.DeepProbe{
		ID: "https", Group: "Web", Name: "HTTPS [Banner]",
		ServiceName: "Web Server",
		DefaultPort: 443, Transport: "TCP", Run: probeHTTPS,
	})
}

func probeHTTP(_ context.Context, ip string, port int, dial scan.DialFunc, emit func(string)) ([]scan.Observation, error) {
	emit(fmt.Sprintf("Connecting to %s (HTTP)…", joinHost(ip, port)))
	conn, err := dialTCP(context.Background(), dial, ip, port, 5*time.Second)
	if err != nil {
		emit("Connection failed: " + err.Error())
		return nil, nil
	}
	defer conn.Close()
	emit("Connected. Sending GET /…")
	conn.SetDeadline(time.Now().Add(5 * time.Second)) //nolint:errcheck

	status, server, ct, _ := httpGetDirect(conn, ip)
	var result []scan.Observation
	if status != "" {
		emit("Status:       " + status)
		result = append(result, obs("probe", "http_status", status))
	}
	if server != "" {
		emit("Server:       " + server)
		result = append(result, obs("probe", "http_server", server))
	}
	if ct != "" {
		emit("Content-Type: " + ct)
	}
	return result, nil
}

func probeHTTPS(_ context.Context, ip string, port int, dial scan.DialFunc, emit func(string)) ([]scan.Observation, error) {
	emit(fmt.Sprintf("Connecting to %s (HTTPS/TLS)…", joinHost(ip, port)))
	tc, err := dialTCP(context.Background(), dial, ip, port, 5*time.Second)
	if err != nil {
		emit("Connection failed: " + err.Error())
		return nil, nil
	}
	defer tc.Close()

	emit("TLS handshake…")
	tlsConn := tls.Client(tc, &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec
		ServerName:         ip,
	})
	tlsConn.SetDeadline(time.Now().Add(5 * time.Second)) //nolint:errcheck
	if err := tlsConn.Handshake(); err != nil {
		emit("TLS handshake failed: " + err.Error())
		return nil, nil
	}

	state := tlsConn.ConnectionState()
	var result []scan.Observation

	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		cn := cert.Subject.CommonName
		issuer := ""
		if len(cert.Issuer.Organization) > 0 {
			issuer = cert.Issuer.Organization[0]
		} else {
			issuer = cert.Issuer.CommonName
		}
		emit(fmt.Sprintf("Certificate:  %s  (issued by %s)", cn, issuer))
		expires := cert.NotAfter.Format("2006-01-02")
		if cert.NotAfter.Before(time.Now()) {
			emit("⚠  EXPIRED on " + expires)
		} else {
			emit("Expires:      " + expires)
		}
		result = append(result, obs("probe", "tls_subject", cn))
		result = append(result, obs("probe", "tls_issuer", issuer))
		result = append(result, obs("probe", "tls_expires", expires))
	}

	emit("Sending GET /…")
	tlsConn.SetDeadline(time.Now().Add(5 * time.Second)) //nolint:errcheck
	// *tls.Conn implements net.Conn, so httpGetDirect works directly.
	status, server, ct, _ := httpGetDirect(tlsConn, ip)
	if status != "" {
		emit("Status:       " + status)
		result = append(result, obs("probe", "https_status", status))
	}
	if server != "" {
		emit("Server:       " + server)
		result = append(result, obs("probe", "https_server", server))
	}
	if ct != "" {
		emit("Content-Type: " + ct)
	}
	return result, nil
}
