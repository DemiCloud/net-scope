package scan

import "regexp"

// ---------------------------------------------------------------------------
// Signature engine — converts raw Observations into DerivedClaims.
//
// Design invariants:
//   - Confidence is monotonic: once set it can only increase, never decrease.
//   - Claims are append-only: existing capabilities/fingerprints are enriched,
//     not replaced.
//   - Port numbers alone are not sufficient for high confidence.
//   - High confidence (≥90) requires protocol-positive evidence (banner, TLS
//     handshake, successful probe response, etc.).
//   - Fingerprint (identity) claims and capability claims are independent; a
//     matching product name does not automatically imply a protocol capability.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Internal types
// ---------------------------------------------------------------------------

// matcher tests a single condition against a Service.
//
// Evaluation rules:
//   - If Source and Key are both empty, the matcher is a port-only check:
//     pass when len(Ports) == 0 OR Service.Port is in Ports.
//   - Otherwise look up obs[Source][Key]:
//     - If Absent: pass when the value is empty/missing.
//     - If compiled != nil: pass when the regex matches the value.
//     - Otherwise: pass when the value is non-empty.
//   - When both Key and Ports are set the port list is checked in addition
//     to the obs condition (both must pass).
type matcher struct {
	source   string
	key      string
	pattern  string // raw regexp pattern; "" = existence/absence check
	absent   bool
	ports    []int
	compiled *regexp.Regexp // set by compileSig; nil when pattern is ""
}

// emitSpec describes one DerivedClaim to produce when a signature fires.
type emitSpec struct {
	cap        string        // capability name (mutually exclusive with fp)
	fp         string        // fingerprint/identity label (mutually exclusive with cap)
	value      string        // optional label value
	confidence uint8         // target confidence (max-monotonic applied)
	evidence   []EvidenceRef // evidence refs to attach to the claim
}

// sigDef is a compiled signature rule.
type sigDef struct {
	name     string
	matchAll []matcher // all must pass (AND)
	matchAny []matcher // at least one must pass, if non-empty (OR within this list)
	emit     []emitSpec
}

// ---------------------------------------------------------------------------
// Built-in signature table
// ---------------------------------------------------------------------------

// builtinSigs is initialised once by init(). Regexes are pre-compiled.
var builtinSigs []sigDef

func init() {
	builtinSigs = compileSigs(rawSigs)
}

// compileSigs pre-compiles all regex patterns in the raw signature list.
func compileSigs(raw []sigDef) []sigDef {
	out := make([]sigDef, len(raw))
	copy(out, raw)
	for i := range out {
		compileSig(&out[i])
	}
	return out
}

func compileSig(s *sigDef) {
	for j := range s.matchAll {
		if p := s.matchAll[j].pattern; p != "" {
			s.matchAll[j].compiled = regexp.MustCompile(p)
		}
	}
	for j := range s.matchAny {
		if p := s.matchAny[j].pattern; p != "" {
			s.matchAny[j].compiled = regexp.MustCompile(p)
		}
	}
}

// ev is a convenience helper for building EvidenceRef slices inline.
func ev(src, key, note string) EvidenceRef { return EvidenceRef{Source: src, Key: key, Note: note} }

// rawSigs is the canonical list of built-in signatures. All regex patterns
// are compiled at package init time by compileSigs.
var rawSigs = []sigDef{

	// -----------------------------------------------------------------------
	// HTTPS capability
	// -----------------------------------------------------------------------

	// Highest confidence: TLS handshake + ALPN h2/http/1.1 is definitive.
	{
		name: "https_alpn",
		matchAll: []matcher{
			{source: "banner", key: "tls_cert"},
			{source: "banner", key: "alpn", pattern: `^(h2|http/1\.1)$`},
		},
		emit: []emitSpec{{
			cap: "https", confidence: 99,
			evidence: []EvidenceRef{
				ev("banner", "tls_cert", "TLS handshake succeeded"),
				ev("banner", "alpn", "ALPN h2/http/1.1 confirms HTTPS"),
			},
		}},
	},

	// TLS handshake + HTTP Server header over TLS.
	{
		name: "https_tls_server",
		matchAll: []matcher{
			{source: "banner", key: "tls_cert"},
			{source: "banner", key: "http_server"},
		},
		emit: []emitSpec{{
			cap: "https", confidence: 95,
			evidence: []EvidenceRef{
				ev("banner", "tls_cert", "TLS handshake succeeded"),
				ev("banner", "http_server", "HTTP Server header received over TLS"),
			},
		}},
	},

	// TLS handshake with no further evidence (certificate present).
	{
		name: "https_tls",
		matchAll: []matcher{
			{source: "banner", key: "tls_cert"},
			{source: "banner", key: "http_server", absent: true},
			{source: "banner", key: "alpn", absent: true},
		},
		emit: []emitSpec{{
			cap: "https", confidence: 90,
			evidence: []EvidenceRef{
				ev("banner", "tls_cert", "TLS handshake succeeded"),
			},
		}},
	},

	// mDNS _https._tcp type hint (discovery-only; lower confidence).
	{
		name: "mdns_https",
		matchAll: []matcher{
			{source: "mdns", key: "type", pattern: `(?i)^_https\._tcp`},
		},
		emit: []emitSpec{{
			cap: "https", confidence: 70,
			evidence: []EvidenceRef{
				ev("mdns", "type", "mDNS _https._tcp advertisement"),
			},
		}},
	},

	// -----------------------------------------------------------------------
	// HTTP capability
	// -----------------------------------------------------------------------

	// Server header received over plain HTTP (no TLS).
	{
		name: "http_plain",
		matchAll: []matcher{
			{source: "banner", key: "http_server"},
			{source: "banner", key: "tls_cert", absent: true},
		},
		emit: []emitSpec{{
			cap: "http", confidence: 95,
			evidence: []EvidenceRef{
				ev("banner", "http_server", "HTTP Server header received on plaintext connection"),
			},
		}},
	},

	// mDNS _http._tcp type hint.
	{
		name: "mdns_http",
		matchAll: []matcher{
			{source: "mdns", key: "type", pattern: `(?i)^_http\._tcp`},
		},
		emit: []emitSpec{{
			cap: "http", confidence: 60,
			evidence: []EvidenceRef{
				ev("mdns", "type", "mDNS _http._tcp advertisement"),
			},
		}},
	},

	// SSDP: UPnP/SSDP is always HTTP-based (devices serve on an HTTP port).
	{
		name: "ssdp_http",
		matchAll: []matcher{
			{source: "ssdp", key: "type"},
		},
		emit: []emitSpec{{
			cap: "http", confidence: 70,
			evidence: []EvidenceRef{
				ev("ssdp", "type", "SSDP/UPnP device always serves HTTP"),
			},
		}},
	},

	// -----------------------------------------------------------------------
	// SSH capability
	// -----------------------------------------------------------------------

	{
		name: "ssh",
		matchAny: []matcher{
			{source: "banner", key: "banner", pattern: `(?i)^SSH-`},
			{source: "banner", key: "name", pattern: `(?i)^(OpenSSH|Dropbear|SSH)$`},
		},
		emit: []emitSpec{{
			cap: "ssh", confidence: 99,
			evidence: []EvidenceRef{
				ev("banner", "banner", "SSH protocol identifier line"),
			},
		}},
	},

	// -----------------------------------------------------------------------
	// SMB capability
	// -----------------------------------------------------------------------

	{
		name: "smb",
		matchAll: []matcher{
			{source: "banner", key: "smb_dialect"},
		},
		emit: []emitSpec{{
			cap: "smb", confidence: 99,
			evidence: []EvidenceRef{
				ev("banner", "smb_dialect", "SMBv2 NEGOTIATE response confirmed"),
			},
		}},
	},

	// -----------------------------------------------------------------------
	// FTP capability
	// -----------------------------------------------------------------------

	{
		name: "ftp",
		matchAny: []matcher{
			{source: "banner", key: "name", pattern: `(?i)\bftp\b|vsftpd|proftpd|pureftpd`},
			{source: "banner", key: "banner", pattern: `(?i)vsftpd|proftpd|pureftpd|\bftp\b|^220[- ]`},
		},
		emit: []emitSpec{{
			cap: "ftp", confidence: 95,
			evidence: []EvidenceRef{
				ev("banner", "banner", "FTP service greeting"),
			},
		}},
	},

	// mDNS _ftp._tcp hint.
	{
		name: "mdns_ftp",
		matchAll: []matcher{
			{source: "mdns", key: "type", pattern: `(?i)^_ftp\._tcp`},
		},
		emit: []emitSpec{{
			cap: "ftp", confidence: 65,
			evidence: []EvidenceRef{ev("mdns", "type", "mDNS _ftp._tcp advertisement")},
		}},
	},

	// -----------------------------------------------------------------------
	// SMTP capability
	// -----------------------------------------------------------------------

	{
		name: "smtp",
		matchAny: []matcher{
			{source: "banner", key: "name", pattern: `(?i)\b(smtp|postfix|sendmail|exim|dovecot|exchange)\b`},
			{source: "banner", key: "banner", pattern: `(?i)\b(smtp|esmtp)\b`},
		},
		emit: []emitSpec{{
			cap: "smtp", confidence: 95,
			evidence: []EvidenceRef{
				ev("banner", "banner", "SMTP/ESMTP service greeting"),
			},
		}},
	},

	// -----------------------------------------------------------------------
	// DNS capability
	// -----------------------------------------------------------------------

	{
		name: "dns",
		matchAny: []matcher{
			{source: "banner", key: "dns_recursion"},
			{source: "banner", key: "dns_server"},
		},
		emit: []emitSpec{{
			cap: "dns", confidence: 99,
			evidence: []EvidenceRef{
				ev("banner", "dns_recursion", "DNS query/response confirmed"),
			},
		}},
	},

	// -----------------------------------------------------------------------
	// LDAP capability
	// -----------------------------------------------------------------------

	{
		name: "ldap",
		matchAny: []matcher{
			{source: "banner", key: "ldap_domain"},
			{source: "banner", key: "ldap_version"},
		},
		emit: []emitSpec{{
			cap: "ldap", confidence: 99,
			evidence: []EvidenceRef{
				ev("banner", "ldap_domain", "LDAP RootDSE response confirmed"),
			},
		}},
	},

	// -----------------------------------------------------------------------
	// MQTT capability
	// -----------------------------------------------------------------------

	{
		name: "mqtt",
		matchAll: []matcher{
			{source: "banner", key: "mqtt_anon"},
		},
		emit: []emitSpec{{
			cap: "mqtt", confidence: 99,
			evidence: []EvidenceRef{
				ev("banner", "mqtt_anon", "MQTT CONNACK received"),
			},
		}},
	},

	// -----------------------------------------------------------------------
	// RDP capability
	// -----------------------------------------------------------------------

	{
		name: "rdp",
		matchAny: []matcher{
			{source: "banner", key: "banner", pattern: `(?i)^RDP`},
			{source: "banner", key: "name", pattern: `(?i)remote desktop`},
		},
		emit: []emitSpec{{
			cap: "rdp", confidence: 95,
			evidence: []EvidenceRef{
				ev("banner", "banner", "RDP TPKT probe confirmed"),
			},
		}},
	},

	// -----------------------------------------------------------------------
	// Telnet capability
	// -----------------------------------------------------------------------

	{
		name: "telnet",
		matchAny: []matcher{
			{source: "banner", key: "name", pattern: `(?i)\btelnet\b`},
		},
		emit: []emitSpec{{
			cap: "telnet", confidence: 85,
			evidence: []EvidenceRef{
				ev("banner", "name", "Telnet service identified"),
			},
		}},
	},

	// -----------------------------------------------------------------------
	// AMQP capability
	// -----------------------------------------------------------------------

	{
		name: "amqp",
		matchAny: []matcher{
			{source: "banner", key: "name", pattern: `(?i)\bamqp\b|rabbitmq`},
			{source: "mdns", key: "type", pattern: `(?i)^_amqp\._tcp`},
		},
		emit: []emitSpec{{
			cap: "amqp", confidence: 90,
			evidence: []EvidenceRef{
				ev("banner", "name", "AMQP service identified"),
			},
		}},
	},

	// -----------------------------------------------------------------------
	// Identity fingerprints (what software product is running)
	// -----------------------------------------------------------------------

	// nginx
	{
		name: "fp_nginx",
		matchAny: []matcher{
			{source: "banner", key: "name", pattern: `(?i)\bnginx\b`},
			{source: "banner", key: "http_server", pattern: `(?i)\bnginx\b`},
			{source: "banner", key: "banner", pattern: `(?i)\bnginx\b`},
		},
		emit: []emitSpec{{
			fp: "nginx", confidence: 95,
			evidence: []EvidenceRef{
				ev("banner", "name", "nginx product name in service identification"),
			},
		}},
	},

	// Apache HTTPD
	{
		name: "fp_apache",
		matchAny: []matcher{
			{source: "banner", key: "name", pattern: `(?i)\bapache\b`},
			{source: "banner", key: "http_server", pattern: `(?i)\bapache\b`},
		},
		emit: []emitSpec{{
			fp: "apache", confidence: 95,
			evidence: []EvidenceRef{
				ev("banner", "name", "Apache identified in service banner"),
			},
		}},
	},

	// OpenSSH
	{
		name: "fp_openssh",
		matchAny: []matcher{
			{source: "banner", key: "name", pattern: `(?i)openssh`},
			{source: "banner", key: "banner", pattern: `(?i)openssh`},
		},
		emit: []emitSpec{{
			fp: "openssh", confidence: 95,
			evidence: []EvidenceRef{
				ev("banner", "banner", "OpenSSH version string in SSH banner"),
			},
		}},
	},

	// Dropbear SSH
	{
		name: "fp_dropbear",
		matchAny: []matcher{
			{source: "banner", key: "name", pattern: `(?i)dropbear`},
			{source: "banner", key: "banner", pattern: `(?i)dropbear`},
		},
		emit: []emitSpec{{
			fp: "dropbear", confidence: 95,
			evidence: []EvidenceRef{
				ev("banner", "banner", "Dropbear SSH identified"),
			},
		}},
	},

	// Microsoft IIS
	{
		name: "fp_iis",
		matchAny: []matcher{
			{source: "banner", key: "name", pattern: `(?i)microsoft.iis|\biis\b|\biis/\d`},
			{source: "banner", key: "http_server", pattern: `(?i)microsoft.iis`},
		},
		emit: []emitSpec{{
			fp: "iis", confidence: 95,
			evidence: []EvidenceRef{
				ev("banner", "name", "Microsoft IIS identified"),
			},
		}},
	},

	// lighttpd
	{
		name: "fp_lighttpd",
		matchAny: []matcher{
			{source: "banner", key: "name", pattern: `(?i)\blighttpd\b`},
			{source: "banner", key: "http_server", pattern: `(?i)\blighttpd\b`},
		},
		emit: []emitSpec{{
			fp: "lighttpd", confidence: 95,
			evidence: []EvidenceRef{
				ev("banner", "name", "lighttpd identified"),
			},
		}},
	},

	// Caddy
	{
		name: "fp_caddy",
		matchAny: []matcher{
			{source: "banner", key: "name", pattern: `(?i)\bcaddy\b`},
			{source: "banner", key: "http_server", pattern: `(?i)\bcaddy\b`},
		},
		emit: []emitSpec{{
			fp: "caddy", confidence: 90,
			evidence: []EvidenceRef{
				ev("banner", "name", "Caddy server identified"),
			},
		}},
	},

	// Traefik
	{
		name: "fp_traefik",
		matchAny: []matcher{
			{source: "banner", key: "name", pattern: `(?i)\btraefik\b`},
			{source: "banner", key: "http_server", pattern: `(?i)\btraefik\b`},
		},
		emit: []emitSpec{{
			fp: "traefik", confidence: 90,
			evidence: []EvidenceRef{
				ev("banner", "name", "Traefik reverse proxy identified"),
			},
		}},
	},

	// HAProxy
	{
		name: "fp_haproxy",
		matchAny: []matcher{
			{source: "banner", key: "name", pattern: `(?i)\bhaproxy\b`},
			{source: "banner", key: "http_server", pattern: `(?i)\bhaproxy\b`},
		},
		emit: []emitSpec{{
			fp: "haproxy", confidence: 90,
			evidence: []EvidenceRef{
				ev("banner", "name", "HAProxy load balancer identified"),
			},
		}},
	},

	// OpenResty (nginx-based)
	{
		name: "fp_openresty",
		matchAny: []matcher{
			{source: "banner", key: "name", pattern: `(?i)\bopenresty\b`},
			{source: "banner", key: "http_server", pattern: `(?i)\bopenresty\b`},
		},
		emit: []emitSpec{{
			fp: "openresty", confidence: 90,
			evidence: []EvidenceRef{
				ev("banner", "name", "OpenResty identified"),
			},
		}},
	},

	// Postfix SMTP
	{
		name: "fp_postfix",
		matchAny: []matcher{
			{source: "banner", key: "name", pattern: `(?i)\bpostfix\b`},
			{source: "banner", key: "banner", pattern: `(?i)\bpostfix\b`},
		},
		emit: []emitSpec{{
			fp: "postfix", confidence: 90,
			evidence: []EvidenceRef{
				ev("banner", "banner", "Postfix MTA identified"),
			},
		}},
	},

	// Exim MTA
	{
		name: "fp_exim",
		matchAny: []matcher{
			{source: "banner", key: "name", pattern: `(?i)\bexim\b`},
			{source: "banner", key: "banner", pattern: `(?i)\bexim\b`},
		},
		emit: []emitSpec{{
			fp: "exim", confidence: 90,
			evidence: []EvidenceRef{
				ev("banner", "banner", "Exim MTA identified"),
			},
		}},
	},

	// vsftpd
	{
		name: "fp_vsftpd",
		matchAny: []matcher{
			{source: "banner", key: "name", pattern: `(?i)vsftpd`},
			{source: "banner", key: "banner", pattern: `(?i)vsftpd`},
		},
		emit: []emitSpec{{
			fp: "vsftpd", confidence: 90,
			evidence: []EvidenceRef{
				ev("banner", "banner", "vsftpd FTP server identified"),
			},
		}},
	},

	// ProFTPD
	{
		name: "fp_proftpd",
		matchAny: []matcher{
			{source: "banner", key: "name", pattern: `(?i)proftpd`},
			{source: "banner", key: "banner", pattern: `(?i)proftpd`},
		},
		emit: []emitSpec{{
			fp: "proftpd", confidence: 90,
			evidence: []EvidenceRef{
				ev("banner", "banner", "ProFTPD FTP server identified"),
			},
		}},
	},
}

// ---------------------------------------------------------------------------
// Evaluation
// ---------------------------------------------------------------------------

// ApplySignatures evaluates all built-in signatures against s and updates
// s.Capabilities and s.Fingerprints. This function is idempotent and
// monotonic: repeated calls can only raise confidence, never lower it.
func ApplySignatures(s *Service) {
	if s.Capabilities == nil {
		s.Capabilities = make(map[string]DerivedClaim)
	}
	if s.Fingerprints == nil {
		s.Fingerprints = make(map[string]DerivedClaim)
	}
	for i := range builtinSigs {
		sig := &builtinSigs[i]
		if !matchesSig(s, sig) {
			continue
		}
		for _, e := range sig.emit {
			if e.cap != "" {
				mergeClaim(s.Capabilities, e.cap, e.confidence, e.value, e.evidence)
			}
			if e.fp != "" {
				mergeClaim(s.Fingerprints, e.fp, e.confidence, e.value, e.evidence)
			}
		}
	}
}

// matchesSig returns true when all MatchAll matchers pass AND at least one
// MatchAny matcher passes (when MatchAny is non-empty).
func matchesSig(s *Service, sig *sigDef) bool {
	for i := range sig.matchAll {
		if !evalMatcher(s, &sig.matchAll[i]) {
			return false
		}
	}
	if len(sig.matchAny) == 0 {
		return true
	}
	for i := range sig.matchAny {
		if evalMatcher(s, &sig.matchAny[i]) {
			return true
		}
	}
	return false
}

// evalMatcher checks a single matcher condition.
func evalMatcher(s *Service, m *matcher) bool {
	// Port-only check (source and key both empty).
	if m.source == "" && m.key == "" {
		if len(m.ports) == 0 {
			return true
		}
		for _, p := range m.ports {
			if s.Port == p {
				return true
			}
		}
		return false
	}

	// Obs lookup.
	val := obsVal(s, m.source, m.key)

	// Optional port filter (AND with obs check).
	if len(m.ports) > 0 {
		found := false
		for _, p := range m.ports {
			if s.Port == p {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	if m.absent {
		return val == ""
	}
	if m.compiled != nil {
		return m.compiled.MatchString(val)
	}
	return val != ""
}

// obsVal returns the value for (source, key) from s.Obs, or "" if not found.
func obsVal(s *Service, source, key string) string {
	for _, o := range s.Obs {
		if o.Source == source && o.Key == key {
			return o.Value
		}
	}
	return ""
}

// copyClaimMap deep-copies a map[string]DerivedClaim, including each
// DerivedClaim's Evidence slice, so the copy is safe to send over a channel
// while the original may still be modified.
func copyClaimMap(m map[string]DerivedClaim) map[string]DerivedClaim {
	if len(m) == 0 {
		return nil
	}
	out := make(map[string]DerivedClaim, len(m))
	for k, dc := range m {
		dcCopy := dc
		if len(dc.Evidence) > 0 {
			dcCopy.Evidence = make([]EvidenceRef, len(dc.Evidence))
			copy(dcCopy.Evidence, dc.Evidence)
		}
		out[k] = dcCopy
	}
	return out
}

// mergeClaim is the monotonic upsert for a single DerivedClaim in a map.
// Confidence only increases. Evidence refs are always accumulated (deduplicated
// by Source+Key+Note).
func mergeClaim(m map[string]DerivedClaim, name string, conf uint8, val string, evs []EvidenceRef) {
	existing := m[name]
	if conf < existing.Confidence {
		// Never lower confidence; still accumulate evidence below.
		goto addEvidence
	}
	if conf > existing.Confidence {
		existing.Confidence = conf
		if val != "" {
			existing.Value = val
		}
	}
addEvidence:
	for _, r := range evs {
		dup := false
		for _, e := range existing.Evidence {
			if e.Source == r.Source && e.Key == r.Key && e.Note == r.Note {
				dup = true
				break
			}
		}
		if !dup {
			existing.Evidence = append(existing.Evidence, r)
		}
	}
	m[name] = existing
}
