package scan

import (
	"bytes"
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"
)

func makeTestResult() Result {
	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
	return Result{
		IP:        net.ParseIP("192.168.1.10").To4(),
		Alive:     true,
		MAC:       mac,
		Vendor:    "Acme Corp",
		Hostname:  "host.local",
		NetBIOS:   "WORKSTATION1",
		OS:        OSWindows,
		OpenPorts: []int{80, 443},
		Latency:   12 * time.Millisecond,
		TTL:       128,
		Banner:    BannerInfo{HTTP: "Apache/2.4", SSH: "OpenSSH_9.3"},
		SNMP: &SNMPInfo{
			SysDescr:    "Linux 5.15",
			SysName:     "router",
			SysLocation: "server room",
			SysContact:  "admin@example.com",
		},
		Services: []ServiceInfo{
			{Source: "mdns", Name: "Printer", Type: "_ipp._tcp"},
		},
	}
}

func TestWriteJSON_AllFields(t *testing.T) {
	r := makeTestResult()
	var buf bytes.Buffer
	if err := WriteJSON(&buf, []Result{r}); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}

	var out []map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("JSON decode: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("expected 1 result, got %d", len(out))
	}
	obj := out[0]

	for _, key := range []string{"ip", "alive", "mac", "vendor", "hostname", "netbios", "os",
		"open_ports", "latency_ms", "ttl", "banner", "snmp", "services"} {
		if _, ok := obj[key]; !ok {
			t.Errorf("JSON output missing field %q", key)
		}
	}

	if obj["ip"] != "192.168.1.10" {
		t.Errorf("ip = %v, want 192.168.1.10", obj["ip"])
	}
	if obj["mac"] != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("mac = %v", obj["mac"])
	}
	if obj["os"] != "Windows" {
		t.Errorf("os = %v, want Windows", obj["os"])
	}
	if obj["ttl"].(float64) != 128 {
		t.Errorf("ttl = %v, want 128", obj["ttl"])
	}

	banner := obj["banner"].(map[string]interface{})
	if banner["http"] != "Apache/2.4" {
		t.Errorf("banner.http = %v", banner["http"])
	}
	if banner["ssh"] != "OpenSSH_9.3" {
		t.Errorf("banner.ssh = %v", banner["ssh"])
	}

	snmp := obj["snmp"].(map[string]interface{})
	if snmp["sys_name"] != "router" {
		t.Errorf("snmp.sys_name = %v", snmp["sys_name"])
	}

	services := obj["services"].([]interface{})
	if len(services) != 1 {
		t.Errorf("services len = %d, want 1", len(services))
	}
}

func TestWriteCSV_AllFields(t *testing.T) {
	r := makeTestResult()
	var buf bytes.Buffer
	if err := WriteCSV(&buf, []Result{r}); err != nil {
		t.Fatalf("WriteCSV: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines (header + 1 row), got %d", len(lines))
	}

	header := lines[0]
	for _, col := range []string{"ip", "mac", "vendor", "hostname", "netbios", "os",
		"open_ports", "latency_ms", "ttl",
		"banner_ssh", "banner_http", "snmp_descr", "snmp_name", "services"} {
		if !strings.Contains(header, col) {
			t.Errorf("CSV header missing column %q", col)
		}
	}

	row := lines[1]
	if !strings.Contains(row, "192.168.1.10") {
		t.Error("CSV row missing IP")
	}
	if !strings.Contains(row, "aa:bb:cc:dd:ee:ff") {
		t.Error("CSV row missing MAC")
	}
	if !strings.Contains(row, "Windows") {
		t.Error("CSV row missing OS")
	}
	if !strings.Contains(row, "Apache/2.4") {
		t.Error("CSV row missing HTTP banner")
	}
}

func TestWriteJSON_DownHost(t *testing.T) {
	r := Result{IP: net.ParseIP("10.0.0.1").To4(), Alive: false}
	var buf bytes.Buffer
	if err := WriteJSON(&buf, []Result{r}); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	var out []map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("JSON decode: %v", err)
	}
	if alive, _ := out[0]["alive"].(bool); alive {
		t.Error("down host should have alive=false")
	}
}

func TestWriteCSV_Empty(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteCSV(&buf, nil); err != nil {
		t.Fatalf("WriteCSV empty: %v", err)
	}
	// Should still have a header row.
	if !strings.Contains(buf.String(), "ip") {
		t.Error("empty CSV should still have header row")
	}
}
