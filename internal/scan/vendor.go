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
	"sort"
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

// ---------------------------------------------------------------------------
// OUI database — sorted flat slice with longest-prefix binary search
//
// Each ouiRecord holds a 5-byte key that encodes the prefix length:
//
//   byte 0   MAC byte 0
//   byte 1   MAC byte 1
//   byte 2   MAC byte 2
//   byte 3   upper-nibble of byte 3 (MA-M/MA-S only; 0x00 for MA-L)
//   byte 4   upper-nibble of byte 4 (MA-S/IAB only; 0x00 for MA-L/MA-M)
//
// This layout means a single sort order covers all prefix lengths without
// ambiguity.  Lookup performs up to three binary searches (MA-S → MA-M → MA-L),
// returning the longest match — exactly like a trie but with no pointer chasing.
// ---------------------------------------------------------------------------

type ouiRecord struct {
	key  [5]byte
	name string
}

var (
	ouiDB    []ouiRecord
	ouiMu    sync.RWMutex
	ouiReady = make(chan struct{}) // closed when DB is loaded (or load has failed)
	ouiOnce  sync.Once
	ouiFrom  string // "embedded" or absolute path of the file used
)

// ouiKeyMAL returns the 5-byte lookup key for a MA-L (24-bit) prefix.
func ouiKeyMAL(mac []byte) [5]byte {
	return [5]byte{mac[0], mac[1], mac[2], 0x00, 0x00}
}

// ouiKeyMAM returns the 5-byte lookup key for a MA-M (28-bit) prefix.
// mac must have at least 4 bytes.
func ouiKeyMAM(mac []byte) [5]byte {
	return [5]byte{mac[0], mac[1], mac[2], mac[3] & 0xF0, 0x00}
}

// ouiKeyMAS returns the 5-byte lookup key for a MA-S/IAB (36-bit) prefix.
// mac must have at least 5 bytes.
func ouiKeyMAS(mac []byte) [5]byte {
	return [5]byte{mac[0], mac[1], mac[2], mac[3], mac[4] & 0xF0}
}

// ouiKeyCmp compares two 5-byte OUI keys lexicographically.
// Returns -1, 0, or 1.
func ouiKeyCmp(a, b [5]byte) int {
	for i := 0; i < 5; i++ {
		if a[i] < b[i] {
			return -1
		}
		if a[i] > b[i] {
			return 1
		}
	}
	return 0
}

// ouiSearch returns the vendor name for a 5-byte key, or "".
func ouiSearch(db []ouiRecord, key [5]byte) string {
	i := sort.Search(len(db), func(i int) bool {
		return ouiKeyCmp(db[i].key, key) >= 0
	})
	if i < len(db) && db[i].key == key {
		return db[i].name
	}
	return ""
}

// ouiPrefixToKey converts a text MAC prefix ("AA:BB:CC", "AA:BB:CC:D",
// "AA:BB:CC:DD:E") into a 5-byte record key for insertion.
// Returns (key, true) or (zero, false) on parse error.
func ouiPrefixToKey(prefix string) ([5]byte, bool) {
	s := strings.ToUpper(strings.ReplaceAll(prefix, "-", ""))
	s = strings.ReplaceAll(s, ":", "")
	var z [5]byte
	switch len(s) {
	case 6: // MA-L
		b, err := hexDecode3(s)
		if err {
			return z, false
		}
		return [5]byte{b[0], b[1], b[2], 0x00, 0x00}, true
	case 7: // MA-M
		b, err := hexDecode3(s[:6])
		nib, nerr := hexNibble(s[6])
		if err || nerr {
			return z, false
		}
		return [5]byte{b[0], b[1], b[2], nib << 4, 0x00}, true
	case 9: // MA-S / IAB
		b, err := hexDecode4(s[:8])
		nib, nerr := hexNibble(s[8])
		if err || nerr {
			return z, false
		}
		return [5]byte{b[0], b[1], b[2], b[3], nib << 4}, true
	}
	return z, false
}

func hexDecode3(s string) ([3]byte, bool) {
	a, ok1 := hexByte2(s[0], s[1])
	b, ok2 := hexByte2(s[2], s[3])
	c, ok3 := hexByte2(s[4], s[5])
	return [3]byte{a, b, c}, !(ok1 && ok2 && ok3)
}

func hexDecode4(s string) ([4]byte, bool) {
	a, ok1 := hexByte2(s[0], s[1])
	b, ok2 := hexByte2(s[2], s[3])
	c, ok3 := hexByte2(s[4], s[5])
	d, ok4 := hexByte2(s[6], s[7])
	return [4]byte{a, b, c, d}, !(ok1 && ok2 && ok3 && ok4)
}

func hexByte2(hi, lo byte) (byte, bool) {
	h, ok1 := hexNibble(hi)
	l, ok2 := hexNibble(lo)
	return h<<4 | l, ok1 && ok2
}

func hexNibble(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
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
// It performs longest-prefix matching: MA-S (36-bit) → MA-M (28-bit) → MA-L (24-bit).
func lookupVendor(mac net.HardwareAddr) string {
	if len(mac) < 3 {
		return ""
	}
	select {
	case <-ouiReady:
	default:
		return ""
	}
	ouiMu.RLock()
	db := ouiDB
	ouiMu.RUnlock()

	if len(mac) >= 5 {
		if v := ouiSearch(db, ouiKeyMAS(mac)); v != "" {
			return v
		}
	}
	if len(mac) >= 4 {
		if v := ouiSearch(db, ouiKeyMAM(mac)); v != "" {
			return v
		}
	}
	return ouiSearch(db, ouiKeyMAL(mac))
}

func loadOUI(dataDir string) ([]ouiRecord, string) {
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

func parseOUIJSON(path string) ([]ouiRecord, string) {
	f, err := os.Open(path)
	if err != nil {
		return nil, ""
	}
	defer f.Close()
	return parseOUIJSONReader(f), path
}

func parseOUIJSONReader(r io.Reader) []ouiRecord {
	var entries []ouiEntry
	if err := json.NewDecoder(r).Decode(&entries); err != nil {
		return nil
	}
	db := make([]ouiRecord, 0, len(entries))
	for _, e := range entries {
		if e.VendorName == "" {
			continue
		}
		if key, ok := ouiPrefixToKey(e.MacPrefix); ok {
			db = append(db, ouiRecord{key: key, name: e.VendorName})
		}
	}
	sort.Slice(db, func(i, j int) bool { return ouiKeyCmp(db[i].key, db[j].key) < 0 })
	return db
}

// parseOUIBin decodes the compact binary OUI format produced by scripts/gen-oui-bin.py.
//
// Record layout (sorted ascending by 5-byte key, packed end-to-end):
//
//	[5 bytes key][1 byte name length N][N bytes vendor name UTF-8]
func parseOUIBin(r io.Reader) []ouiRecord {
	data, err := io.ReadAll(r)
	if err != nil || len(data) == 0 {
		return nil
	}
	db := make([]ouiRecord, 0, len(data)/28) // ~28 bytes average per record
	for i := 0; i+6 <= len(data); {
		var key [5]byte
		copy(key[:], data[i:i+5])
		nlen := int(data[i+5])
		i += 6
		if i+nlen > len(data) {
			break
		}
		if nlen > 0 {
			db = append(db, ouiRecord{key: key, name: string(data[i : i+nlen])})
		}
		i += nlen
	}
	// Binary file is pre-sorted; no sort needed here.
	return db
}

// ---------------------------------------------------------------------------
// Legacy oui.txt parser — kept for user-supplied files in the old IEEE format.
// ---------------------------------------------------------------------------

func parseOUIFile(path string) ([]ouiRecord, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var db []ouiRecord
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
		if key, ok := ouiPrefixToKey(raw); ok {
			db = append(db, ouiRecord{key: key, name: vendor})
		}
	}
	sort.Slice(db, func(i, j int) bool { return ouiKeyCmp(db[i].key, db[j].key) < 0 })
	return db, scanner.Err()
}

