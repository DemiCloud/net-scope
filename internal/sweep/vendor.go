package sweep

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	// OUIFileName is the name of the user-downloaded OUI file stored in DataDir.
	OUIFileName = "oui.json"

	// OUISourceURL is the default download source.
	OUISourceURL = "https://maclookup.app/downloads/json-database/get-db?version=latest"
)

var (
	ouiDB    map[string]string
	ouiMu    sync.RWMutex
	ouiReady = make(chan struct{}) // closed when DB is loaded (or load has failed)
	ouiOnce  sync.Once
	ouiFrom  string // "embedded" or absolute path of the file used
)

// InitVendorDB starts loading the OUI database in the background.
// dataDir is the directory where a user-downloaded oui.json may exist.
// Pass "" to use only the embedded data.
func InitVendorDB(dataDir string) {
	ouiOnce.Do(func() {
		go func() {
			defer close(ouiReady)
			db, from := loadOUI(dataDir)
			ouiMu.Lock()
			ouiDB = db
			ouiFrom = from
			ouiMu.Unlock()
		}()
	})
}

// OUIStatus returns a human-readable description of the loaded OUI database.
// Blocks briefly if called before the DB has finished loading; returns immediately
// if called after.
func OUIStatus(dataDir string) string {
	select {
	case <-ouiReady:
	case <-time.After(200 * time.Millisecond):
		return "Loading…"
	}
	ouiMu.RLock()
	n := len(ouiDB)
	from := ouiFrom
	ouiMu.RUnlock()

	if n == 0 {
		return "Not loaded"
	}
	if from == "embedded" {
		return fmt.Sprintf("Embedded data — %d entries (built-in)", n)
	}
	// Show mod time of the user file.
	info, err := os.Stat(from)
	if err != nil {
		return fmt.Sprintf("File: %s — %d entries", filepath.Base(from), n)
	}
	return fmt.Sprintf("File: %s — %d entries (updated %s)", filepath.Base(from), n, info.ModTime().Format("2006-01-02"))
}

// DownloadOUIDB downloads a fresh OUI database to dataDir/oui.json.
// Returns the path written and any error.
func DownloadOUIDB(dataDir string) (string, error) {
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return "", fmt.Errorf("create data dir: %w", err)
	}
	dest := filepath.Join(dataDir, OUIFileName)

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Get(OUISourceURL)
	if err != nil {
		return "", fmt.Errorf("download: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("download: HTTP %d", resp.StatusCode)
	}

	tmp, err := os.CreateTemp(dataDir, "oui-*.json.tmp")
	if err != nil {
		return "", fmt.Errorf("temp file: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)

	if _, err := io.Copy(tmp, resp.Body); err != nil {
		tmp.Close()
		return "", fmt.Errorf("write: %w", err)
	}
	tmp.Close()

	if err := os.Rename(tmpPath, dest); err != nil {
		return "", fmt.Errorf("rename: %w", err)
	}

	// Reload the database from the new file.
	ouiMu.Lock()
	ouiDB, ouiFrom = parseOUIJSON(dest)
	ouiMu.Unlock()

	return dest, nil
}

// lookupVendor returns the IEEE OUI vendor name for a MAC address.
// Returns "" immediately if the DB isn't loaded yet — it never blocks.
func lookupVendor(mac net.HardwareAddr) string {
	if len(mac) < 3 {
		return ""
	}
	select {
	case <-ouiReady:
	default:
		return ""
	}
	prefix := fmt.Sprintf("%02X:%02X:%02X", mac[0], mac[1], mac[2])
	ouiMu.RLock()
	v := ouiDB[prefix]
	ouiMu.RUnlock()
	return v
}

func loadOUI(dataDir string) (map[string]string, string) {
	// Prefer user-downloaded file if it exists.
	if dataDir != "" {
		p := filepath.Join(dataDir, OUIFileName)
		if _, err := os.Stat(p); err == nil {
			if db, from := parseOUIJSON(p); len(db) > 0 {
				return db, from
			}
		}
	}
	// Fall back to embedded data.
	return parseOUIJSONReader(strings.NewReader(string(embeddedOUI))), "embedded"
}

// ouiEntry matches the maclookup.app JSON schema.
type ouiEntry struct {
	MacPrefix  string `json:"macPrefix"`
	VendorName string `json:"vendorName"`
}

func parseOUIJSON(path string) (map[string]string, string) {
	f, err := os.Open(path)
	if err != nil {
		return nil, ""
	}
	defer f.Close()
	return parseOUIJSONReader(f), path
}

func parseOUIJSONReader(r io.Reader) map[string]string {
	var entries []ouiEntry
	if err := json.NewDecoder(r).Decode(&entries); err != nil {
		return nil
	}
	db := make(map[string]string, len(entries))
	for _, e := range entries {
		prefix := strings.ToUpper(e.MacPrefix)
		if e.VendorName != "" {
			db[prefix] = e.VendorName
		}
	}
	return db
}

// ---------------------------------------------------------------------------
// Legacy oui.txt parser — kept for user-supplied files in the old IEEE format.
// ---------------------------------------------------------------------------

func parseOUIFile(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	db := make(map[string]string, 40000)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.Contains(line, "(hex)") {
			continue
		}
		parts := strings.SplitN(line, "\t\t", 2)
		if len(parts) != 2 {
			continue
		}
		// Convert XX-XX-XX → XX:XX:XX for uniform key format.
		raw := strings.ToUpper(strings.TrimSpace(strings.Fields(parts[0])[0]))
		prefix := strings.ReplaceAll(raw, "-", ":")
		vendor := strings.TrimSpace(parts[1])
		if len(prefix) == 8 {
			db[prefix] = vendor
		}
	}
	return db, scanner.Err()
}

