package scan

import (
	"regexp"
	"strings"
)

// Weights for service identification signals. The same scoring algorithm as
// guessOS is used: score = max(weights) + min((n−1)×5, maxBonus) where n is
// the number of votes for the winning product.
const (
	wSvcServerExact   = 90 // Server: header with explicit version (e.g. "nginx/1.27.4")
	wSvcServerGeneric = 72 // Server: header matches product but no parseable version
	wSvcSSHExact      = 85 // SSH version string with recognised product
	wSvcSSHGeneric    = 55 // SSH version string present but product unrecognised
	wSvcBannerExact   = 80 // FTP/SMTP/Telnet greeting with recognised product + version
	wSvcBannerGeneric = 62 // FTP/SMTP/Telnet greeting with recognised product only
	wSvcRDP           = 85 // RDP TPKT probe confirmed the port is RDP
	wSvcCert          = 48 // TLS certificate subject/issuer implies product
	// Protocol-confirmed signals — highest confidence tier.
	// A successful protocol handshake is near-definitive; version strings within
	// such responses lift confidence to the top of the range.
	wSvcSMBProbe  = 93 // SMBv2 NEGOTIATE response confirmed
	wSvcDNSProbe  = 88 // DNS query response (valid DNS message) confirmed
	wSvcLDAPProbe = 88 // LDAP RootDSE response confirmed
	wSvcMQTTProbe = 90 // MQTT CONNACK received (valid broker confirmed)
	minSvcScore   = 22 // minimum score required to report anything
)

// svcPriors is the static, embedded service-port prior table.
// Checked last; provides a weak default label for well-known port numbers.
var svcPriors = [...]struct {
	port    int
	product string
	weight  int
}{
	{21, "FTP", 18}, {22, "SSH", 18}, {23, "Telnet", 18},
	{25, "SMTP", 18}, {53, "DNS", 18}, {80, "HTTP", 12},
	{110, "POP3", 18}, {143, "IMAP", 18}, {161, "SNMP", 18},
	{389, "LDAP", 18}, {443, "HTTPS", 12}, {445, "SMB", 20},
	{465, "SMTPS", 18}, {587, "SMTP", 18}, {636, "LDAPS", 18},
	{993, "IMAPS", 18}, {995, "POP3S", 18},
	{1433, "Microsoft SQL Server", 28}, {1521, "Oracle DB", 28},
	{3306, "MySQL", 28}, {3389, "Remote Desktop", 28},
	{5432, "PostgreSQL", 28}, {5672, "AMQP", 28},
	{5900, "VNC", 22}, {6379, "Redis", 28},
	{8080, "HTTP", 10}, {8443, "HTTPS", 10},
	{8883, "MQTT", 22}, {9200, "Elasticsearch", 28},
	{11211, "Memcached", 28}, {27017, "MongoDB", 28},
}

// svcHTTPSigs is the static HTTP Server-header signature table.
// Entries are checked in order; first match wins.
// An empty product means: extract the product name from the "Name/Version"
// token in the Server header directly (preserving the original capitalisation).
var svcHTTPSigs = [...]struct {
	pattern string // lowercase substring to search for
	product string // canonical display name; "" = extract from raw token
}{
	// Specific compound names must appear before their shorter prefixes.
	{"apache-coyote", "Apache Tomcat"},
	{"microsoft-httpapi", "Microsoft HTTP API"},
	{"microsoft-iis", "Microsoft IIS"},
	{"openresty", "OpenResty"},
	{"amazons3", "Amazon S3"},
	{"akamaitechnologies", "Akamai"},
	{"cloudflare", "Cloudflare"},
	{"traefik", "Traefik"},
	{"kong", "Kong"},
	{"envoy", "Envoy"},
	{"haproxy", "HAProxy"},
	{"squid", "Squid"},
	{"varnish", "Varnish"},
	{"kestrel", "ASP.NET Kestrel"},
	{"mini_httpd", "mini_httpd"},
	{"thttpd", "thttpd"},
	{"hiawatha", "Hiawatha"},
	{"h2o", "H2O"},
	{"tengine", "Tengine"},
	{"cowboy", "Cowboy"},
	{"werkzeug", "Werkzeug"},
	{"gunicorn", "Gunicorn"},
	{"uvicorn", "Uvicorn"},
	{"aiohttp", "aiohttp"},
	{"jetty", "Jetty"},
	{"tomcat", "Apache Tomcat"},
	{"gws", "Google Web Server"},
	// Products that embed version as "name/X.Y.Z" — empty product extracts from header.
	{"nginx", ""},
	{"apache", "Apache HTTPD"},
	{"lighttpd", ""},
	{"caddy", ""},
	{"iis", "Microsoft IIS"},
	{"php", "PHP"},
	{"node.js", "Node.js"},
	{"tornado", "Tornado"},
	{"fasthttp", "fasthttp"},
}

// svcSSHSigs is the static SSH banner signature table.
// Input is the software string after stripping the "SSH-2.0-" prefix.
var svcSSHSigs = [...]struct {
	pattern string
	product string
}{
	{"rosssh", "RouterOS SSH"},
	{"cisco-", "Cisco SSH"},
	{"openssh", "OpenSSH"},
	{"dropbear", "Dropbear SSH"},
	{"libssh", "libssh"},
	{"bitvise", "Bitvise SSH"},
	{"putty", "PuTTY SSH"},
	{"mod_sftp", "OpenSSH (mod_sftp)"},
	{"servu", "Serv-U SSH"},
	{"freesshd", "freeSSHd"},
	{"huawei-sshd", "Huawei SSH"},
	{"paramiko", "Paramiko"},
	{"lancom", "Lancom SSH"},
}

// svcLineSigs is the static FTP / SMTP / Telnet greeting signature table.
var svcLineSigs = [...]struct {
	pattern string
	product string
}{
	// FTP
	{"vsftpd", "vsFTPd"},
	{"proftpd", "ProFTPD"},
	{"filezilla server", "FileZilla Server"},
	{"pure-ftpd", "Pure-FTPd"},
	{"pure ftpd", "Pure-FTPd"},
	{"microsoft ftp", "Microsoft FTP Service"},
	{"wu-ftpd", "wu-ftpd"},
	{"bftpd", "Bftpd"},
	{"ncftpd", "NcFTPd"},
	// SMTP
	{"postfix", "Postfix"},
	{"sendmail", "Sendmail"},
	{"exim", "Exim"},
	{"microsoft esmtp", "Microsoft Exchange"},
	{"microsoft exchange", "Microsoft Exchange"},
	{"dovecot", "Dovecot"},
	{"qmail", "qmail"},
	{"haraka", "Haraka"},
	{"zimbra", "Zimbra"},
	// Telnet / generic line protocols
	{"busybox", "BusyBox"},
	{"cisco", "Cisco"},
	{"mikrotik", "MikroTik"},
	{"routeros", "RouterOS"},
}

// reVersionInBanner extracts a version-like token (e.g. "9.3p2", "2022.83",
// "1.27.4") from banner strings. Anchored at a word boundary to avoid partial
// matches inside hex strings or timestamps.
var reVersionInBanner = regexp.MustCompile(`\b(\d+\.\d[\d\.p-]*)\b`)

// guessService identifies the product and version running on a single TCP port.
// All string inputs may be empty; the function handles any combination.
// details carries protocol-specific key/value data from deeper probes (SMB,
// DNS, LDAP, MQTT) — it may be nil.
// Returns (product, version, confidence) where confidence is 0–100.
// A zero confidence means no signal met the minimum threshold.
func guessService(port int, banner, serverHeader, tlsCert, alpn string, details map[string]string) (product, version string, confidence uint8) {
	type vote struct {
		product string
		version string
		weight  int
	}
	var votes []vote
	add := func(p, v string, w int) {
		if p != "" && w > 0 {
			votes = append(votes, vote{p, v, w})
		}
	}

	// ---- HTTP Server: header (highest confidence for web services) ----
	if serverHeader != "" {
		p, v := parseServerHeader(serverHeader)
		w := wSvcServerGeneric
		if v != "" {
			w = wSvcServerExact
		}
		add(p, v, w)
	}

	// ---- SSH version string ----
	if banner != "" {
		if p, v := parseSSHBanner(banner); p != "" {
			w := wSvcSSHExact
			if v == "" {
				w = wSvcSSHGeneric
			}
			add(p, v, w)
		}
	}

	// ---- RDP TPKT probe ----
	if banner == "RDP (TPKT)" {
		add("Remote Desktop", "", wSvcRDP)
	}

	// ---- FTP / SMTP / Telnet line banner ----
	// Only consulted when there is no server header (avoids FTP on port 21
	// conflicting with a web service that happens to serve a short response).
	if banner != "" && serverHeader == "" {
		if p, v := parseLineBanner(banner); p != "" {
			w := wSvcBannerGeneric
			if v != "" {
				w = wSvcBannerExact
			}
			add(p, v, w)
		}
	}

	// ---- TLS certificate hint ----
	if tlsCert != "" {
		if p := certProductHint(tlsCert); p != "" {
			add(p, "", wSvcCert)
		}
	}

	// ---- ALPN hint ----
	if alpn == "h2" {
		add("HTTP/2", "", 35)
	} else if alpn == "http/1.1" {
		add("HTTPS", "", 30)
	}

	// ---- Protocol-confirmed signals from deep probes ----
	// These are the highest-confidence signals: a successful protocol handshake
	// is near-definitive identification, independent of port number.
	if len(details) > 0 {
		if d, ok := details["smb_dialect"]; ok && d != "" {
			// SMBv2 NEGOTIATE succeeded — this is definitively SMB.
			// The dialect string (e.g. "SMB 3.1.1") becomes the version.
			add("SMB", d, wSvcSMBProbe)
			// SMBv1 still enabled is a security finding; surface it.
			if details["smb1"] == "true" {
				add("SMB (v1 enabled)", d, wSvcSMBProbe)
			}
		}
		if _, ok := details["dns_recursion"]; ok {
			// A valid DNS query response confirms this is a DNS resolver.
			// Use the version.bind string as the version if available.
			dnsVer := details["dns_server"]
			add("DNS", dnsVer, wSvcDNSProbe)
		}
		if domain, ok := details["ldap_domain"]; ok {
			// LDAP RootDSE confirmed; domain name goes in the version field
			// (most useful display for AD environments).
			add("LDAP", domain, wSvcLDAPProbe)
		} else if _, ok := details["ldap_version"]; ok {
			add("LDAP", details["ldap_version"], wSvcLDAPProbe)
		}
		if anon, ok := details["mqtt_anon"]; ok && anon != "" {
			add("MQTT", "", wSvcMQTTProbe)
		}
	}

	// ---- Port prior (last resort, weakest signal) ----
	for _, pr := range svcPriors {
		if pr.port == port {
			add(pr.product, "", pr.weight)
			break
		}
	}

	if len(votes) == 0 {
		return "", "", 0
	}

	// Find the highest-weight vote.
	best := votes[0]
	for _, v := range votes[1:] {
		if v.weight > best.weight {
			best = v
		}
	}

	// Count corroborating votes for the same product (case-insensitive).
	n := 0
	for _, v := range votes {
		if strings.EqualFold(v.product, best.product) {
			n++
		}
	}
	bonus := (n - 1) * 5
	if bonus > maxBonus {
		bonus = maxBonus
	}
	score := best.weight + bonus
	if score < minSvcScore {
		return "", "", 0
	}
	conf := score
	if conf > 100 {
		conf = 100
	}

	// Use the best version available within the winning product cluster.
	ver := best.version
	if ver == "" {
		for _, v := range votes {
			if strings.EqualFold(v.product, best.product) && v.version != "" {
				ver = v.version
				break
			}
		}
	}
	return best.product, ver, uint8(conf)
}

// parseServerHeader extracts (product, version) from an HTTP Server: header.
// Handles "nginx/1.27.4", "Apache/2.4.54 (Unix)", "Microsoft-IIS/10.0", etc.
func parseServerHeader(header string) (product, version string) {
	lower := strings.ToLower(strings.TrimSpace(header))
	if lower == "" {
		return "", ""
	}

	// The first whitespace/paren-delimited token often carries "Product/Version".
	firstTok := header
	if i := strings.IndexAny(header, " ("); i > 0 {
		firstTok = header[:i]
	}

	// Check against the known signature table.
	for _, sig := range svcHTTPSigs {
		if !strings.Contains(lower, sig.pattern) {
			continue
		}

		p := sig.product
		ver := ""

		// Try to extract a numeric version from "product/X.Y.Z" in the first token.
		if sl := strings.IndexByte(firstTok, '/'); sl >= 0 {
			candidate := firstTok[sl+1:]
			if len(candidate) > 0 && candidate[0] >= '0' && candidate[0] <= '9' {
				ver = candidate
			}
		}

		// Entries with an empty canonical name: derive product from the raw token.
		if p == "" {
			if sl := strings.IndexByte(firstTok, '/'); sl > 0 {
				p = firstTok[:sl]
			} else {
				p = firstTok
			}
		}

		return p, ver
	}

	// Generic "Product/Version" fallback for unrecognised servers.
	if sl := strings.IndexByte(firstTok, '/'); sl > 0 {
		rawP, rawV := firstTok[:sl], firstTok[sl+1:]
		if len(rawV) > 0 && rawV[0] >= '0' && rawV[0] <= '9' {
			return rawP, rawV
		}
	}

	// Last resort: use the whole first token as a product name, no version.
	if len(firstTok) > 0 && len(firstTok) <= 80 {
		return firstTok, ""
	}
	return "", ""
}

// parseSSHBanner extracts (product, version) from an SSH software string.
// The input is already stripped of the "SSH-2.0-" protocol prefix — it is
// just the software version comment, e.g. "OpenSSH_9.3p2 Ubuntu-1ubuntu3.3".
func parseSSHBanner(raw string) (product, version string) {
	lower := strings.ToLower(raw)
	for _, sig := range svcSSHSigs {
		if !strings.Contains(lower, sig.pattern) {
			continue
		}
		ver := ""
		if m := reVersionInBanner.FindString(raw); m != "" {
			ver = m
		}
		return sig.product, ver
	}
	return "", ""
}

// parseLineBanner extracts (product, version) from FTP / SMTP / Telnet greetings.
func parseLineBanner(banner string) (product, version string) {
	lower := strings.ToLower(banner)
	for _, sig := range svcLineSigs {
		if strings.Contains(lower, sig.pattern) {
			ver := ""
			if m := reVersionInBanner.FindString(banner); m != "" {
				ver = m
			}
			return sig.product, ver
		}
	}
	return "", ""
}

// certProductHint returns a weak product hint from a TLS certificate descriptor.
// Returns empty string when no recognisable vendor name is found.
func certProductHint(cert string) string {
	lower := strings.ToLower(cert)
	switch {
	case strings.Contains(lower, "microsoft"):
		return "Microsoft"
	case strings.Contains(lower, "nginx"):
		return "nginx"
	case strings.Contains(lower, "apache"):
		return "Apache"
	case strings.Contains(lower, "cisco"):
		return "Cisco"
	case strings.Contains(lower, "juniper"):
		return "Juniper"
	case strings.Contains(lower, "ubiquiti"), strings.Contains(lower, "unifi"):
		return "Ubiquiti"
	case strings.Contains(lower, "mikrotik"):
		return "MikroTik"
	case strings.Contains(lower, "fortinet"):
		return "Fortinet"
	case strings.Contains(lower, "palo alto"):
		return "Palo Alto"
	}
	return ""
}
