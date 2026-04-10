package scan

import (
	"testing"
	"time"
)

// helper builds a minimal Service with the given obs entries.
func svcWith(port int, obs ...Observation) *Service {
	return &Service{
		ID:        "test-id",
		IP:        "192.168.1.1",
		Port:      port,
		FirstSeen: time.Now(),
		LastSeen:  time.Now(),
		Obs:       obs,
	}
}

func o(src, key, val string) Observation { return Observation{Source: src, Key: key, Value: val} }

// ---------------------------------------------------------------------------
// HTTPS capability
// ---------------------------------------------------------------------------

func TestHTTPS_ALPN_h2(t *testing.T) {
	svc := svcWith(443,
		o("banner", "tls_cert", "example.com (Let's Encrypt)"),
		o("banner", "alpn", "h2"),
	)
	ApplySignatures(svc)
	cap, ok := svc.Capabilities["https"]
	if !ok {
		t.Fatal("expected https capability")
	}
	if cap.Confidence != 99 {
		t.Errorf("https confidence = %d, want 99", cap.Confidence)
	}
}

func TestHTTPS_ALPN_http11(t *testing.T) {
	svc := svcWith(443,
		o("banner", "tls_cert", "example.com (Let's Encrypt)"),
		o("banner", "alpn", "http/1.1"),
	)
	ApplySignatures(svc)
	cap := svc.Capabilities["https"]
	if cap.Confidence != 99 {
		t.Errorf("https confidence = %d, want 99", cap.Confidence)
	}
}

func TestHTTPS_TLS_with_server_header(t *testing.T) {
	svc := svcWith(443,
		o("banner", "tls_cert", "secure.example.com (Acme)"),
		o("banner", "http_server", "nginx/1.27.4"),
	)
	ApplySignatures(svc)
	cap := svc.Capabilities["https"]
	if cap.Confidence < 95 {
		t.Errorf("https confidence = %d, want ≥95", cap.Confidence)
	}
}

func TestHTTPS_TLS_only(t *testing.T) {
	svc := svcWith(8883,
		o("banner", "tls_cert", "iot.local (Self-signed)"),
	)
	ApplySignatures(svc)
	cap := svc.Capabilities["https"]
	if cap.Confidence < 90 {
		t.Errorf("https confidence = %d, want ≥90", cap.Confidence)
	}
}

func TestHTTPS_ALPN_beats_TLSonly(t *testing.T) {
	// Apply TLS-only first, then ALPN — confidence should reach 99.
	svc := svcWith(443,
		o("banner", "tls_cert", "example.com"),
	)
	ApplySignatures(svc)
	if svc.Capabilities["https"].Confidence == 99 {
		t.Fatal("should not be 99 yet without ALPN")
	}
	// Now add ALPN obs and re-apply.
	svc.Obs = append(svc.Obs, o("banner", "alpn", "h2"))
	ApplySignatures(svc)
	if svc.Capabilities["https"].Confidence != 99 {
		t.Errorf("after ALPN added, confidence = %d, want 99", svc.Capabilities["https"].Confidence)
	}
}

func TestHTTPS_mDNS_hint(t *testing.T) {
	svc := svcWith(0,
		o("mdns", "type", "_https._tcp"),
	)
	ApplySignatures(svc)
	cap := svc.Capabilities["https"]
	if cap.Confidence != 70 {
		t.Errorf("mdns https confidence = %d, want 70", cap.Confidence)
	}
}

// ---------------------------------------------------------------------------
// HTTP capability
// ---------------------------------------------------------------------------

func TestHTTP_plain_server_header(t *testing.T) {
	svc := svcWith(80,
		o("banner", "http_server", "Apache/2.4.51"),
		// No tls_cert.
	)
	ApplySignatures(svc)
	cap := svc.Capabilities["http"]
	if cap.Confidence != 95 {
		t.Errorf("http confidence = %d, want 95", cap.Confidence)
	}
}

func TestHTTP_plain_does_not_fire_with_TLS(t *testing.T) {
	// If TLS is present, http_plain should NOT fire (it's https, not http).
	svc := svcWith(443,
		o("banner", "tls_cert", "example.com"),
		o("banner", "http_server", "nginx/1.27"),
	)
	ApplySignatures(svc)
	// http_plain requires tls_cert ABSENT — should not fire.
	if _, ok := svc.Capabilities["http"]; ok {
		t.Errorf("http_plain should not fire when TLS is present; got http confidence = %d",
			svc.Capabilities["http"].Confidence)
	}
}

func TestHTTP_mDNS_hint(t *testing.T) {
	svc := svcWith(0,
		o("mdns", "type", "_http._tcp"),
	)
	ApplySignatures(svc)
	cap := svc.Capabilities["http"]
	if cap.Confidence != 60 {
		t.Errorf("mdns http confidence = %d, want 60", cap.Confidence)
	}
}

func TestHTTP_SSDP(t *testing.T) {
	svc := svcWith(1900,
		o("ssdp", "type", "urn:schemas-upnp-org:device:MediaRenderer:1"),
	)
	ApplySignatures(svc)
	cap := svc.Capabilities["http"]
	if cap.Confidence < 65 {
		t.Errorf("ssdp http confidence = %d, want ≥65", cap.Confidence)
	}
}

func TestHTTP_mDNS_overridden_by_probe(t *testing.T) {
	// mDNS gives 60; actual HTTP probe raises it to 95.
	svc := svcWith(80,
		o("mdns", "type", "_http._tcp"),
	)
	ApplySignatures(svc)
	if svc.Capabilities["http"].Confidence != 60 {
		t.Fatalf("expected 60 before probe, got %d", svc.Capabilities["http"].Confidence)
	}
	svc.Obs = append(svc.Obs, o("banner", "http_server", "nginx/1.24"))
	ApplySignatures(svc)
	if svc.Capabilities["http"].Confidence != 95 {
		t.Errorf("after probe, http confidence = %d, want 95", svc.Capabilities["http"].Confidence)
	}
}

// ---------------------------------------------------------------------------
// SSH capability
// ---------------------------------------------------------------------------

func TestSSH_raw_banner(t *testing.T) {
	svc := svcWith(22,
		o("banner", "banner", "SSH-2.0-OpenSSH_9.3p2 Ubuntu-1"),
	)
	ApplySignatures(svc)
	cap := svc.Capabilities["ssh"]
	if cap.Confidence != 99 {
		t.Errorf("ssh confidence = %d, want 99", cap.Confidence)
	}
}

func TestSSH_name_match(t *testing.T) {
	svc := svcWith(22,
		o("banner", "name", "OpenSSH"),
	)
	ApplySignatures(svc)
	if svc.Capabilities["ssh"].Confidence != 99 {
		t.Errorf("ssh via name = %d, want 99", svc.Capabilities["ssh"].Confidence)
	}
}

func TestSSH_Dropbear(t *testing.T) {
	svc := svcWith(22,
		o("banner", "banner", "SSH-2.0-dropbear_2022.83"),
	)
	ApplySignatures(svc)
	if svc.Capabilities["ssh"].Confidence != 99 {
		t.Errorf("dropbear ssh confidence = %d, want 99", svc.Capabilities["ssh"].Confidence)
	}
}

func TestSSH_no_false_positive(t *testing.T) {
	svc := svcWith(22,
		o("banner", "name", "FTP"),
	)
	ApplySignatures(svc)
	if _, ok := svc.Capabilities["ssh"]; ok {
		t.Errorf("ssh should not fire for FTP service")
	}
}

// ---------------------------------------------------------------------------
// SMB capability
// ---------------------------------------------------------------------------

func TestSMB(t *testing.T) {
	svc := svcWith(445,
		o("banner", "smb_dialect", "SMB 3.1.1"),
	)
	ApplySignatures(svc)
	cap := svc.Capabilities["smb"]
	if cap.Confidence != 99 {
		t.Errorf("smb confidence = %d, want 99", cap.Confidence)
	}
}

func TestSMB_no_dialect_no_fire(t *testing.T) {
	svc := svcWith(445)
	ApplySignatures(svc)
	if _, ok := svc.Capabilities["smb"]; ok {
		t.Errorf("smb should not fire without dialect probe")
	}
}

// ---------------------------------------------------------------------------
// FTP capability
// ---------------------------------------------------------------------------

func TestFTP_banner(t *testing.T) {
	svc := svcWith(21,
		o("banner", "banner", "220 (vsFTPd 3.0.5)"),
	)
	ApplySignatures(svc)
	cap := svc.Capabilities["ftp"]
	if cap.Confidence < 90 {
		t.Errorf("ftp confidence = %d, want ≥90", cap.Confidence)
	}
}

func TestFTP_name(t *testing.T) {
	svc := svcWith(21,
		o("banner", "name", "vsftpd"),
	)
	ApplySignatures(svc)
	if svc.Capabilities["ftp"].Confidence < 90 {
		t.Errorf("ftp via name confidence = %d, want ≥90", svc.Capabilities["ftp"].Confidence)
	}
}

// ---------------------------------------------------------------------------
// SMTP capability
// ---------------------------------------------------------------------------

func TestSMTP_esmtp_banner(t *testing.T) {
	svc := svcWith(25,
		o("banner", "banner", "220 mail.example.com ESMTP Postfix"),
	)
	ApplySignatures(svc)
	if svc.Capabilities["smtp"].Confidence < 90 {
		t.Errorf("smtp confidence = %d, want ≥90", svc.Capabilities["smtp"].Confidence)
	}
}

// ---------------------------------------------------------------------------
// DNS capability
// ---------------------------------------------------------------------------

func TestDNS_recursion(t *testing.T) {
	svc := svcWith(53,
		o("banner", "dns_recursion", "true"),
	)
	ApplySignatures(svc)
	if svc.Capabilities["dns"].Confidence != 99 {
		t.Errorf("dns confidence = %d, want 99", svc.Capabilities["dns"].Confidence)
	}
}

func TestDNS_server_version(t *testing.T) {
	svc := svcWith(53,
		o("banner", "dns_server", "BIND 9.18.1"),
	)
	ApplySignatures(svc)
	if svc.Capabilities["dns"].Confidence != 99 {
		t.Errorf("dns via server version = %d, want 99", svc.Capabilities["dns"].Confidence)
	}
}

// ---------------------------------------------------------------------------
// LDAP capability
// ---------------------------------------------------------------------------

func TestLDAP(t *testing.T) {
	svc := svcWith(389,
		o("banner", "ldap_domain", "corp.example.com"),
	)
	ApplySignatures(svc)
	if svc.Capabilities["ldap"].Confidence != 99 {
		t.Errorf("ldap confidence = %d, want 99", svc.Capabilities["ldap"].Confidence)
	}
}

// ---------------------------------------------------------------------------
// MQTT capability
// ---------------------------------------------------------------------------

func TestMQTT(t *testing.T) {
	svc := svcWith(1883,
		o("banner", "mqtt_anon", "allowed"),
	)
	ApplySignatures(svc)
	if svc.Capabilities["mqtt"].Confidence != 99 {
		t.Errorf("mqtt confidence = %d, want 99", svc.Capabilities["mqtt"].Confidence)
	}
}

// ---------------------------------------------------------------------------
// Identity fingerprints
// ---------------------------------------------------------------------------

func TestFP_nginx(t *testing.T) {
	svc := svcWith(80,
		o("banner", "name", "nginx"),
	)
	ApplySignatures(svc)
	fp := svc.Fingerprints["nginx"]
	if fp.Confidence != 95 {
		t.Errorf("nginx confidence = %d, want 95", fp.Confidence)
	}
}

func TestFP_nginx_versioned(t *testing.T) {
	svc := svcWith(80,
		o("banner", "http_server", "nginx/1.27.4"),
	)
	ApplySignatures(svc)
	if svc.Fingerprints["nginx"].Confidence != 95 {
		t.Errorf("nginx versioned confidence = %d, want 95", svc.Fingerprints["nginx"].Confidence)
	}
}

func TestFP_apache(t *testing.T) {
	svc := svcWith(80,
		o("banner", "name", "Apache HTTPD"),
	)
	ApplySignatures(svc)
	if svc.Fingerprints["apache"].Confidence != 95 {
		t.Errorf("apache confidence = %d, want 95", svc.Fingerprints["apache"].Confidence)
	}
}

func TestFP_openssh(t *testing.T) {
	svc := svcWith(22,
		o("banner", "banner", "SSH-2.0-OpenSSH_9.3p2"),
	)
	ApplySignatures(svc)
	if svc.Fingerprints["openssh"].Confidence != 95 {
		t.Errorf("openssh confidence = %d, want 95", svc.Fingerprints["openssh"].Confidence)
	}
}

func TestFP_iis(t *testing.T) {
	svc := svcWith(80,
		o("banner", "name", "Microsoft IIS"),
	)
	ApplySignatures(svc)
	if svc.Fingerprints["iis"].Confidence != 95 {
		t.Errorf("iis confidence = %d, want 95", svc.Fingerprints["iis"].Confidence)
	}
}

func TestFP_lighttpd(t *testing.T) {
	svc := svcWith(80,
		o("banner", "name", "lighttpd"),
	)
	ApplySignatures(svc)
	if svc.Fingerprints["lighttpd"].Confidence != 95 {
		t.Errorf("lighttpd confidence = %d, want 95", svc.Fingerprints["lighttpd"].Confidence)
	}
}

func TestFP_caddy(t *testing.T) {
	svc := svcWith(443,
		o("banner", "http_server", "Caddy"),
	)
	ApplySignatures(svc)
	if svc.Fingerprints["caddy"].Confidence < 85 {
		t.Errorf("caddy confidence = %d, want ≥85", svc.Fingerprints["caddy"].Confidence)
	}
}

func TestFP_vsftpd(t *testing.T) {
	svc := svcWith(21,
		o("banner", "banner", "220 (vsFTPd 3.0.5)"),
	)
	ApplySignatures(svc)
	if svc.Fingerprints["vsftpd"].Confidence < 85 {
		t.Errorf("vsftpd confidence = %d, want ≥85", svc.Fingerprints["vsftpd"].Confidence)
	}
}

// ---------------------------------------------------------------------------
// Monotonic invariant
// ---------------------------------------------------------------------------

func TestMonotonic_confidence_never_decreases(t *testing.T) {
	svc := svcWith(443,
		o("banner", "tls_cert", "example.com"),
		o("banner", "alpn", "h2"),
	)
	ApplySignatures(svc)
	before := svc.Capabilities["https"].Confidence
	if before != 99 {
		t.Fatalf("expected 99, got %d", before)
	}

	// Remove ALPN and re-apply — confidence must NOT drop.
	for i, obs := range svc.Obs {
		if obs.Key == "alpn" {
			svc.Obs = append(svc.Obs[:i], svc.Obs[i+1:]...)
			break
		}
	}
	ApplySignatures(svc)
	after := svc.Capabilities["https"].Confidence
	if after < before {
		t.Errorf("confidence dropped from %d to %d — violates monotonic invariant", before, after)
	}
}

// ---------------------------------------------------------------------------
// Combined scenario
// ---------------------------------------------------------------------------

func TestFullService_nginx_HTTPS(t *testing.T) {
	// Simulates a fully probed nginx behind TLS on port 443.
	svc := svcWith(443,
		o("banner", "name", "nginx"),
		o("banner", "version", "1.27.4"),
		o("banner", "http_server", "nginx/1.27.4"),
		o("banner", "tls_cert", "example.com (Let's Encrypt)"),
		o("banner", "alpn", "h2"),
	)
	ApplySignatures(svc)

	if svc.Capabilities["https"].Confidence != 99 {
		t.Errorf("https = %d, want 99", svc.Capabilities["https"].Confidence)
	}
	if _, ok := svc.Capabilities["http"]; ok {
		// http_plain requires tls_cert absent — should not fire here.
		t.Errorf("http_plain should not fire when TLS is present")
	}
	if svc.Fingerprints["nginx"].Confidence != 95 {
		t.Errorf("nginx fp = %d, want 95", svc.Fingerprints["nginx"].Confidence)
	}
	// Evidence must be populated.
	if len(svc.Capabilities["https"].Evidence) == 0 {
		t.Error("https evidence slice is empty")
	}
}
