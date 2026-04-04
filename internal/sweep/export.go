package sweep

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
	type jsonResult struct {
		IP        string `json:"ip"`
		Alive     bool   `json:"alive"`
		Hostname  string `json:"hostname,omitempty"`
		OpenPorts []int  `json:"open_ports,omitempty"`
		LatencyMs int64  `json:"latency_ms,omitempty"`
	}

	out := make([]jsonResult, len(results))
	for i, r := range results {
		out[i] = jsonResult{
			IP:        r.IP.String(),
			Alive:     r.Alive,
			Hostname:  r.Hostname,
			OpenPorts: r.OpenPorts,
			LatencyMs: r.Latency.Milliseconds(),
		}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

// WriteCSV encodes results as CSV to w.
func WriteCSV(w io.Writer, results []Result) error {
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"ip", "alive", "hostname", "open_ports", "latency_ms"})
	for _, r := range results {
		ports := make([]string, len(r.OpenPorts))
		for i, p := range r.OpenPorts {
			ports[i] = strconv.Itoa(p)
		}
		err := cw.Write([]string{
			r.IP.String(),
			strconv.FormatBool(r.Alive),
			r.Hostname,
			strings.Join(ports, ";"),
			fmt.Sprintf("%d", r.Latency.Milliseconds()),
		})
		if err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}
