package scan

import (
	"bufio"
	"bytes"
	"compress/gzip"
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
	ouiDB    map[uint32]string
	ouiMu    sync.RWMutex
	ouiReady = make(chan struct{}) // closed when DB is loaded (or load has failed)
	ouiOnce  sync.Once
	ouiFrom  string // "embedded" or absolute path of the file used
)

// macKey packs a 3-byte MAC OUI prefix into a uint32 for map lookup.
// Bits 23–0 hold the three prefix bytes; the upper byte is always zero.
func macKey(b0, b1, b2 byte) uint32 {
	return uint32(b0)<<16 | uint32(b1)<<8 | uint32(b2)
}

// ouiPrefixKey parses a MAC prefix string ("AA:BB:CC" or "AA-BB-CC") into a
// uint32 key. Only exact 3-octet MA-L prefixes are accepted; longer
// MA-M/MA-S prefixes return false so they are silently dropped.
func ouiPrefixKey(prefix string) (uint32, bool) {
	s := strings.ToUpper(strings.ReplaceAll(prefix, "-", ":"))
	parts := strings.Split(s, ":")
	if len(parts) != 3 {
		return 0, false
	}
	b0, ok0 := hexByte(parts[0])
	b1, ok1 := hexByte(parts[1])
	b2, ok2 := hexByte(parts[2])
	if !ok0 || !ok1 || !ok2 {
		return 0, false
	}
	return macKey(b0, b1, b2), true
}

func hexByte(s string) (byte, bool) {
	if len(s) != 2 {
		return 0, false
	}
	hi, ok1 := hexNibble(s[0])
	lo, ok2 := hexNibble(s[1])
	return hi<<4 | lo, ok1 && ok2
}

func hexNibble(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	default:
		return 0, false
	}
}

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

// LookupVendor returns the IEEE OUI vendor name for a MAC address.
// Returns "" immediately if the DB isn't loaded yet — it never blocks.
func LookupVendor(mac net.HardwareAddr) string {
	return lookupVendor(mac)
}

// lookupVendor is the unexported implementation called from within the package.
func lookupVendor(mac net.HardwareAddr) string {
	if len(mac) < 3 {
		return ""
	}
	select {
	case <-ouiReady:
	default:
		return ""
	}
	key := macKey(mac[0], mac[1], mac[2])
	ouiMu.RLock()
	v := ouiDB[key]
	ouiMu.RUnlock()
	return v
}

func loadOUI(dataDir string) (map[uint32]string, string) {
	// Prefer user-downloaded JSON file if it exists.
	if dataDir != "" {
		p := filepath.Join(dataDir, OUIFileName)
		if _, err := os.Stat(p); err == nil {
			if db, from := parseOUIJSON(p); len(db) > 0 {
				return db, from
			}
		}
	}
	// Fall back to embedded compact binary (gzip-compressed in with_oui builds).
	var r io.Reader = bytes.NewReader(embeddedOUI)
	if len(embeddedOUI) >= 2 && embeddedOUI[0] == 0x1f && embeddedOUI[1] == 0x8b {
		gr, err := gzip.NewReader(r)
		if err == nil {
			defer gr.Close()
			r = gr
		}
	}
	return parseOUIBin(r), "embedded"
}

// ouiEntry matches the maclookup.app JSON schema.
type ouiEntry struct {
	MacPrefix  string `json:"macPrefix"`
	VendorName string `json:"vendorName"`
}

func parseOUIJSON(path string) (map[uint32]string, string) {
	f, err := os.Open(path)
	if err != nil {
		return nil, ""
	}
	defer f.Close()
	return parseOUIJSONReader(f), path
}

func parseOUIJSONReader(r io.Reader) map[uint32]string {
	var entries []ouiEntry
	if err := json.NewDecoder(r).Decode(&entries); err != nil {
		return nil
	}
	db := make(map[uint32]string, len(entries))
	for _, e := range entries {
		if e.VendorName == "" {
			continue
		}
		if key, ok := ouiPrefixKey(e.MacPrefix); ok {
			db[key] = e.VendorName
		}
	}
	return db
}

// parseOUIBin decodes the compact binary OUI format produced by scripts/gen-oui-bin.py.
//
// Record layout (no header, packed end-to-end):
//
//	[3 bytes MAC prefix][1 byte name length N][N bytes vendor name UTF-8]
func parseOUIBin(r io.Reader) map[uint32]string {
	data, err := io.ReadAll(r)
	if err != nil || len(data) == 0 {
		return nil
	}
	db := make(map[uint32]string, len(data)/27) // ~27 bytes average per record
	for i := 0; i+4 <= len(data); {
		b0, b1, b2 := data[i], data[i+1], data[i+2]
		nlen := int(data[i+3])
		i += 4
		if i+nlen > len(data) {
			break
		}
		if nlen > 0 {
			db[macKey(b0, b1, b2)] = string(data[i : i+nlen])
		}
		i += nlen
	}
	return db
}

// ---------------------------------------------------------------------------
// Legacy oui.txt parser — kept for user-supplied files in the old IEEE format.
// ---------------------------------------------------------------------------

func parseOUIFile(path string) (map[uint32]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	db := make(map[uint32]string, 40000)
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
		raw := strings.ToUpper(strings.TrimSpace(strings.Fields(parts[0])[0]))
		vendor := strings.TrimSpace(parts[1])
		if key, ok := ouiPrefixKey(raw); ok {
			db[key] = vendor
		}
	}
	return db, scanner.Err()
}

