package scan

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// ReadHostsFile returns all non-comment, non-blank entries from the system
// hosts file. The path is platform-specific (hostsFilePath).
func ReadHostsFile() []HostsEntry {
	f, err := os.Open(hostsFilePath())
	if err != nil {
		return nil
	}
	defer f.Close()

	var out []HostsEntry
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		// Strip inline comment.
		comment := ""
		if idx := strings.IndexByte(line, '#'); idx >= 0 {
			comment = strings.TrimSpace(line[idx+1:])
			line = line[:idx]
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue // blank or comment-only line
		}
		out = append(out, HostsEntry{
			IP:        fields[0],
			Hostnames: fields[1:],
			Comment:   comment,
		})
	}
	return out
}

// AddHostsEntry appends a new entry to the system hosts file.
// Requires write access to the hosts file (administrator/root on most systems).
func AddHostsEntry(ip string, hostnames []string) error {
	if ip == "" || len(hostnames) == 0 {
		return fmt.Errorf("IP and at least one hostname are required")
	}
	path := hostsFilePath()
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read hosts file: %w", err)
	}
	line := ip + "\t" + strings.Join(hostnames, " ")
	content := strings.TrimRight(string(data), "\r\n") + "\n" + line + "\n"
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		return fmt.Errorf("write hosts file: %w", err)
	}
	return nil
}

// DeleteHostsEntry removes the first matching entry from the hosts file.
// target format: "IP\thostname1 hostname2..." — the same string produced
// by hostsEntryTarget in the GUI.
func DeleteHostsEntry(target string) error {
	parts := strings.SplitN(target, "\t", 2)
	if len(parts) != 2 {
		return fmt.Errorf("invalid hosts target %q", target)
	}
	wantIP := strings.TrimSpace(parts[0])
	wantHosts := strings.Fields(parts[1])

	path := hostsFilePath()
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("read hosts file: %w", err)
	}

	var lines []string
	deleted := false
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		raw := scanner.Text()
		stripped := raw
		if idx := strings.IndexByte(raw, '#'); idx >= 0 {
			stripped = raw[:idx]
		}
		fields := strings.Fields(stripped)
		if !deleted && len(fields) >= 2 && strings.EqualFold(fields[0], wantIP) &&
			hostsNamesMatch(fields[1:], wantHosts) {
			deleted = true
			continue // drop this line
		}
		lines = append(lines, raw)
	}
	f.Close()
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read hosts file: %w", err)
	}
	if !deleted {
		return fmt.Errorf("hosts entry not found: %s", target)
	}
	out := strings.Join(lines, "\n")
	if !strings.HasSuffix(out, "\n") {
		out += "\n"
	}
	if err := os.WriteFile(path, []byte(out), 0644); err != nil {
		return fmt.Errorf("write hosts file: %w", err)
	}
	return nil
}

// hostsNamesMatch reports whether got and want contain the same hostnames
// (case-insensitive, order-insensitive).
func hostsNamesMatch(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	wset := make(map[string]struct{}, len(want))
	for _, h := range want {
		wset[strings.ToLower(h)] = struct{}{}
	}
	for _, h := range got {
		if _, ok := wset[strings.ToLower(h)]; !ok {
			return false
		}
	}
	return true
}
