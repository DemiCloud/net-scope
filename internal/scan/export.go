package scan

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// WriteJSON encodes results as a JSON array to w.
func WriteJSON(w io.Writer, results []Result) error {
	type jsonBanner struct {
		HTTP   string `json:"http,omitempty"`
		HTTPS  string `json:"https,omitempty"`
		SSH    string `json:"ssh,omitempty"`
		FTP    string `json:"ftp,omitempty"`
		SMTP   string `json:"smtp,omitempty"`
		Telnet string `json:"telnet,omitempty"`
	}
	type jsonSNMP struct {
		SysDescr    string `json:"sys_descr,omitempty"`
		SysName     string `json:"sys_name,omitempty"`
		SysLocation string `json:"sys_location,omitempty"`
		SysContact  string `json:"sys_contact,omitempty"`
	}
	type jsonService struct {
		Source  string   `json:"source"`
		Name    string   `json:"name,omitempty"`
		Type    string   `json:"type,omitempty"`
		Details []string `json:"details,omitempty"`
	}
	type jsonPortService struct {
		Port       int    `json:"port"`
		Name       string `json:"name,omitempty"`
		Version    string `json:"version,omitempty"`
		Banner     string `json:"banner,omitempty"`
		TLSCert    string `json:"tls_cert,omitempty"`
		ALPN       string `json:"alpn,omitempty"`
		Confidence uint8  `json:"confidence,omitempty"`
	}
	type jsonResult struct {
		IP           string            `json:"ip"`
		Alive        bool              `json:"alive"`
		MAC          string            `json:"mac,omitempty"`
		Vendor       string            `json:"vendor,omitempty"`
		Hostname     string            `json:"hostname,omitempty"`
		NetBIOS      string            `json:"netbios,omitempty"`
		OS           string            `json:"os,omitempty"`
		OpenPorts    []int             `json:"open_ports,omitempty"`
		LatencyMs    int64             `json:"latency_ms,omitempty"`
		TTL          uint8             `json:"ttl,omitempty"`
		Banner       *jsonBanner       `json:"banner,omitempty"`
		PortServices []jsonPortService  `json:"port_services,omitempty"`
		SNMP         *jsonSNMP         `json:"snmp,omitempty"`
		Services     []jsonService      `json:"services,omitempty"`
	}

	out := make([]jsonResult, len(results))
	for i, r := range results {
		jr := jsonResult{
			IP:        r.IP.String(),
			Alive:     r.Alive,
			Hostname:  r.Hostname,
			NetBIOS:   r.NetBIOS,
			OS:        string(r.OS),
			OpenPorts: r.OpenPorts,
			LatencyMs: r.Latency.Milliseconds(),
			TTL:       r.TTL,
		}
		if r.MAC != nil {
			jr.MAC = r.MAC.String()
		}
		jr.Vendor = r.Vendor

		b := r.Banner
		if b.HTTP != "" || b.HTTPS != "" || b.SSH != "" || b.FTP != "" || b.SMTP != "" || b.Telnet != "" {
			jr.Banner = &jsonBanner{
				HTTP: b.HTTP, HTTPS: b.HTTPS, SSH: b.SSH,
				FTP: b.FTP, SMTP: b.SMTP, Telnet: b.Telnet,
			}
		}
		if r.SNMP != nil {
			jr.SNMP = &jsonSNMP{
				SysDescr:    r.SNMP.SysDescr,
				SysName:     r.SNMP.SysName,
				SysLocation: r.SNMP.SysLocation,
				SysContact:  r.SNMP.SysContact,
			}
		}
		for _, ps := range r.PortServices {
			jr.PortServices = append(jr.PortServices, jsonPortService{
				Port:       ps.Port,
				Name:       ps.Name,
				Version:    ps.Version,
				Banner:     ps.Banner,
				TLSCert:    ps.TLSCert,
				ALPN:       ps.ALPN,
				Confidence: ps.Confidence,
			})
		}
		for _, svc := range r.Services {
			jr.Services = append(jr.Services, jsonService{
				Source:  svc.Source,
				Name:    svc.Name,
				Type:    svc.Type,
				Details: svc.Details,
			})
		}
		out[i] = jr
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

// WriteCSV encodes results as CSV to w.
func WriteCSV(w io.Writer, results []Result) error {
	cw := csv.NewWriter(w)
	if err := cw.Write([]string{
		"ip", "alive", "mac", "vendor", "hostname", "netbios", "os",
		"open_ports", "latency_ms", "ttl",
		"banner_ssh", "banner_http", "banner_https", "banner_ftp", "banner_smtp", "banner_telnet",
		"port_services",
		"snmp_descr", "snmp_name", "snmp_location", "snmp_contact",
		"services",
	}); err != nil {
		return err
	}
	for _, r := range results {
		mac := ""
		if r.MAC != nil {
			mac = r.MAC.String()
		}
		ports := make([]string, len(r.OpenPorts))
		for i, p := range r.OpenPorts {
			ports[i] = strconv.Itoa(p)
		}

		snmpDescr, snmpName, snmpLoc, snmpContact := "", "", "", ""
		if r.SNMP != nil {
			snmpDescr = r.SNMP.SysDescr
			snmpName = r.SNMP.SysName
			snmpLoc = r.SNMP.SysLocation
			snmpContact = r.SNMP.SysContact
		}

		var portSvcs []string
		for _, ps := range r.PortServices {
			if ps.Name != "" {
				if ps.Version != "" {
					portSvcs = append(portSvcs, fmt.Sprintf("%d:%s/%s(%d%%)", ps.Port, ps.Name, ps.Version, ps.Confidence))
				} else {
					portSvcs = append(portSvcs, fmt.Sprintf("%d:%s(%d%%)", ps.Port, ps.Name, ps.Confidence))
				}
			}
		}
		var svcs []string
		for _, svc := range r.Services {
			svcs = append(svcs, fmt.Sprintf("[%s] %s (%s)", svc.Source, svc.Name, svc.Type))
		}

		if err := cw.Write([]string{
			r.IP.String(),
			strconv.FormatBool(r.Alive),
			mac,
			r.Vendor,
			r.Hostname,
			r.NetBIOS,
			string(r.OS),
			strings.Join(ports, ";"),
			fmt.Sprintf("%d", r.Latency.Milliseconds()),
			fmt.Sprintf("%d", r.TTL),
			r.Banner.SSH,
			r.Banner.HTTP,
			r.Banner.HTTPS,
			r.Banner.FTP,
			r.Banner.SMTP,
			r.Banner.Telnet,
			strings.Join(portSvcs, "; "),
			snmpDescr, snmpName, snmpLoc, snmpContact,
			strings.Join(svcs, "; "),
		}); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}
