package scan

import (
	"context"
	"encoding/xml"
	"net"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// WS-Discovery (WSD) — passive Hello listener + active Probe
//
// Supports both WSD 2005 (DPWS / older devices) and WSD 2009 (Windows 7+).
// Uses UDP multicast 239.255.255.250:3702.
// ---------------------------------------------------------------------------

const (
	wsdMulticast = "239.255.255.250:3702"

	// WSD 2005 (DPWS — used by older scanners, printers, Windows XP/Vista)
	wsdNS2005     = "http://schemas.xmlsoap.org/ws/2005/04/discovery"
	wsdAddrNS2005 = "http://schemas.xmlsoap.org/ws/2004/08/addressing"

	// WSD 2009 (used by Windows 7+, modern printers, cameras)
	wsdNS2009     = "http://docs.oasis-open.org/ws-dd/ns/discovery/2009/01"
	wsdAddrNS2009 = "http://www.w3.org/2005/08/addressing"
)

// wsdProbeTemplate builds a WS-Discovery Probe message for the given namespace pair.
func wsdProbeTemplate(discNS, addrNS string) string {
	return `<?xml version="1.0" encoding="utf-8"?>` +
		`<soap:Envelope` +
		` xmlns:soap="http://www.w3.org/2003/05/soap-envelope"` +
		` xmlns:wsa="` + addrNS + `"` +
		` xmlns:wsd="` + discNS + `">` +
		`<soap:Header>` +
		`<wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To>` +
		`<wsa:Action>` + discNS + `/Probe</wsa:Action>` +
		`<wsa:MessageID>urn:uuid:net-scope-probe</wsa:MessageID>` +
		`</soap:Header>` +
		`<soap:Body><wsd:Probe><wsd:Types/></wsd:Probe></soap:Body>` +
		`</soap:Envelope>`
}

// ---------------------------------------------------------------------------
// WSDDevice — parsed representation of one WS-Discovery device announcement
// ---------------------------------------------------------------------------

// WSDDevice holds the fields extracted from a WSD Hello or ProbeMatch message.
type WSDDevice struct {
	// EndpointAddr is the UUID URI from the EndpointReference (device identity).
	EndpointAddr string
	// Types is the space-separated list of WSD type URNs (may include
	// wsdp:Device, pub:Computer, print:PrintDeviceType, scan:ScanDeviceType…).
	Types string
	// XAddrs contains the HTTP transport URLs to the device's metadata service.
	XAddrs []string
	// Scopes contains scope URIs (may include manufacturer name, model, etc.).
	Scopes []string
}

// FriendlyTypes returns the Types field with namespace prefixes stripped to
// just the local names, separated by " · ".
func (d WSDDevice) FriendlyTypes() string {
	if d.Types == "" {
		return "—"
	}
	parts := strings.Fields(d.Types)
	names := make([]string, 0, len(parts))
	seen := map[string]bool{}
	for _, p := range parts {
		// Strip namespace prefix: "pub:Computer" → "Computer"
		// or full URI: ".../Computer" → "Computer"
		name := p
		if i := strings.LastIndexAny(p, ":/"); i >= 0 {
			name = p[i+1:]
		}
		if name != "" && name != "Device" && !seen[name] {
			seen[name] = true
			names = append(names, name)
		}
	}
	if len(names) == 0 {
		return "Device"
	}
	return strings.Join(names, " · ")
}

// FriendlyScopes extracts meaningful scope values (manufacturer, model, etc.)
// from the raw scope URI list.
func (d WSDDevice) FriendlyScopes() string {
	var parts []string
	seen := map[string]bool{}
	for _, s := range d.Scopes {
		// e.g. "ldap:///ou=HP%20LaserJet,o=HP" or just "HP LaserJet"
		// strip URL-encoded path components and return meaningful segments
		s = strings.TrimPrefix(s, "ldap:///")
		s = strings.TrimPrefix(s, "http://")
		s = strings.TrimPrefix(s, "https://")
		// Take last path segment
		segs := strings.Split(s, "/")
		seg := segs[len(segs)-1]
		// URL-decode %20 → space (minimal)
		seg = strings.ReplaceAll(seg, "%20", " ")
		// Strip "ou=", "o=" etc
		if idx := strings.Index(seg, "="); idx >= 0 {
			seg = seg[idx+1:]
		}
		if seg != "" && !seen[seg] {
			seen[seg] = true
			parts = append(parts, seg)
		}
	}
	return strings.Join(parts, " · ")
}

// ---------------------------------------------------------------------------
// Discovery
// ---------------------------------------------------------------------------

// discoverWSD sends WSD Probe messages (both 2005 and 2009 namespaces) and
// collects Hello/ProbeMatch responses for the duration of timeout.
// Returns a map of IPv4 string → []ServiceInfo.
func discoverWSD(ctx context.Context, timeout time.Duration) map[string][]ServiceInfo {
	results := make(map[string][]ServiceInfo)

	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return results
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	dst, err := net.ResolveUDPAddr("udp4", wsdMulticast)
	if err != nil {
		return results
	}

	// Send probes for both namespaces.
	for _, probe := range []string{
		wsdProbeTemplate(wsdNS2005, wsdAddrNS2005),
		wsdProbeTemplate(wsdNS2009, wsdAddrNS2009),
	} {
		_, _ = conn.WriteTo([]byte(probe), dst)
	}

	seen := map[string]bool{}
	buf := make([]byte, 65536)

	for {
		if ctx.Err() != nil {
			break
		}
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			break
		}
		ip := addrToIP(addr)
		if ip == nil {
			continue
		}
		dev, ok := parseWSDMessage(buf[:n])
		if !ok {
			continue
		}
		key := ip.String() + dev.EndpointAddr
		if seen[key] {
			continue
		}
		seen[key] = true

		details := make([]string, 0, len(dev.XAddrs)+len(dev.Scopes)+1)
		details = append(details, "endpoint:"+dev.EndpointAddr)
		for _, xa := range dev.XAddrs {
			details = append(details, "xaddr:"+xa)
		}
		for _, sc := range dev.Scopes {
			details = append(details, "scope:"+sc)
		}

		results[ip.String()] = append(results[ip.String()], ServiceInfo{
			Source:  "wsd",
			Name:    dev.FriendlyScopes(),
			Type:    dev.Types,
			Details: details,
		})
	}
	return results
}

// ListenWSDHello joins the WSD multicast group and listens passively for
// Hello announcements until ctx is cancelled, calling cb for each device.
func ListenWSDHello(ctx context.Context, cb func(ip net.IP, svc ServiceInfo)) {
	gaddr, err := net.ResolveUDPAddr("udp4", wsdMulticast)
	if err != nil {
		return
	}
	// Bind to the WSD multicast port on all interfaces.
	conn, err := net.ListenMulticastUDP("udp4", nil, gaddr)
	if err != nil {
		return
	}
	defer conn.Close()

	seen := map[string]bool{}
	buf := make([]byte, 65536)

	for {
		if ctx.Err() != nil {
			return
		}
		conn.SetDeadline(time.Now().Add(2 * time.Second))
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			continue
		}
		ip := addrToIP(addr)
		if ip == nil {
			continue
		}
		dev, ok := parseWSDMessage(buf[:n])
		if !ok {
			continue
		}
		key := ip.String() + dev.EndpointAddr
		if seen[key] {
			continue
		}
		seen[key] = true

		details := make([]string, 0, len(dev.XAddrs)+len(dev.Scopes)+1)
		details = append(details, "endpoint:"+dev.EndpointAddr)
		for _, xa := range dev.XAddrs {
			details = append(details, "xaddr:"+xa)
		}
		for _, sc := range dev.Scopes {
			details = append(details, "scope:"+sc)
		}

		cb(ip, ServiceInfo{
			Source:  "wsd",
			Name:    dev.FriendlyScopes(),
			Type:    dev.Types,
			Details: details,
		})
	}
}

// ---------------------------------------------------------------------------
// XML parsing — minimal SOAP envelope decoder
// ---------------------------------------------------------------------------

// parseWSDMessage extracts device info from a raw WSD SOAP message using
// an XML token scanner. This avoids namespace-prefix confusion that trips
// up encoding/xml's struct decoder on WSD envelopes.
// Returns (device, true) on success.
func parseWSDMessage(data []byte) (WSDDevice, bool) {
	d := wsdTokenScan(data)
	if d.EndpointAddr == "" && d.Types == "" {
		return parseWSDFallback(data)
	}
	return d, true
}

// wsdTokenScan walks the XML token stream and collects the fields we care
// about regardless of namespace prefix.
func wsdTokenScan(data []byte) WSDDevice {
	var d WSDDevice
	dec := xml.NewDecoder(strings.NewReader(string(data)))
	dec.Strict = false
	dec.AutoClose = xml.HTMLAutoClose
	// We want to collect text content of these local names:
	capture := ""
	for {
		tok, err := dec.Token()
		if err != nil {
			break
		}
		switch t := tok.(type) {
		case xml.StartElement:
			capture = t.Name.Local
		case xml.CharData:
			text := strings.TrimSpace(string(t))
			if text == "" {
				break
			}
			switch capture {
			case "Address":
				if d.EndpointAddr == "" {
					d.EndpointAddr = text
				}
			case "Types":
				if d.Types == "" {
					d.Types = text
				}
			case "XAddrs":
				d.XAddrs = append(d.XAddrs, strings.Fields(text)...)
			case "Scopes":
				d.Scopes = append(d.Scopes, strings.Fields(text)...)
			}
		case xml.EndElement:
			capture = ""
		}
	}
	return d
}

// parseWSDFallback extracts device fields from raw XML bytes without full
// parsing, used when the namespace-heavy envelope confuses encoding/xml.
func parseWSDFallback(data []byte) (WSDDevice, bool) {
	s := string(data)
	ep := xmlTextBetween(s, "Address")
	types := xmlTextBetween(s, "Types")
	xaddrs := xmlTextBetween(s, "XAddrs")
	scopes := xmlTextBetween(s, "Scopes")
	if ep == "" && types == "" {
		return WSDDevice{}, false
	}
	d := WSDDevice{EndpointAddr: ep, Types: types}
	if xaddrs != "" {
		d.XAddrs = strings.Fields(xaddrs)
	}
	if scopes != "" {
		d.Scopes = strings.Fields(scopes)
	}
	return d, true
}

// xmlTextBetween returns the text content of the first element with the given
// local name in s, stripping namespace prefixes from the tag.
func xmlTextBetween(s, localName string) string {
	// Match both <Tag> and <ns:Tag> patterns.
	for _, open := range []string{"<" + localName + ">", ":" + localName + ">"} {
		start := strings.Index(s, open)
		if start < 0 {
			continue
		}
		start += len(open)
		// Find closing tag (any namespace prefix).
		end := strings.Index(s[start:], "</")
		if end < 0 {
			continue
		}
		return strings.TrimSpace(s[start : start+end])
	}
	return ""
}

// WsdServiceInfoToDevice reconstructs a WSDDevice from the Details slice
// of a ServiceInfo (for use in the GUI display layer).
func WsdServiceInfoToDevice(svc ServiceInfo) WSDDevice {
	d := WSDDevice{Types: svc.Type}
	for _, detail := range svc.Details {
		switch {
		case strings.HasPrefix(detail, "endpoint:"):
			d.EndpointAddr = strings.TrimPrefix(detail, "endpoint:")
		case strings.HasPrefix(detail, "xaddr:"):
			d.XAddrs = append(d.XAddrs, strings.TrimPrefix(detail, "xaddr:"))
		case strings.HasPrefix(detail, "scope:"):
			d.Scopes = append(d.Scopes, strings.TrimPrefix(detail, "scope:"))
		}
	}
	return d
}
