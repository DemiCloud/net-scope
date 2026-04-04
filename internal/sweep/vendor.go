package sweep

import (
	"bufio"
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
	ouiURL    = "https://standards-oui.ieee.org/oui/oui.txt"
	ouiMaxAge = 30 * 24 * time.Hour
)

var (
	ouiDB    map[string]string
	ouiMu    sync.RWMutex
	ouiReady = make(chan struct{}) // closed when DB is loaded (or load has failed)
	ouiOnce  sync.Once
)

// InitVendorDB starts loading the OUI database in the background.
// Call this once at program startup. lookupVendor works without it
// but will return "" until the DB is ready.
func InitVendorDB() {
	ouiOnce.Do(func() {
		go func() {
			defer close(ouiReady)
			db := loadOUI()
			ouiMu.Lock()
			ouiDB = db
			ouiMu.Unlock()
		}()
	})
}

// lookupVendor returns the IEEE OUI vendor name for a MAC address.
// Returns "" immediately if the DB isn't loaded yet — it never blocks.
func lookupVendor(mac net.HardwareAddr) string {
	if len(mac) < 3 {
		return ""
	}
	// Non-blocking check: is the DB ready?
	select {
	case <-ouiReady:
	default:
		return ""
	}
	prefix := fmt.Sprintf("%02X-%02X-%02X", mac[0], mac[1], mac[2])
	ouiMu.RLock()
	v := ouiDB[prefix]
	ouiMu.RUnlock()
	return v
}

func loadOUI() map[string]string {
	path := ouiCachePath()

	// Fresh cache — parse and return immediately.
	if info, err := os.Stat(path); err == nil && time.Since(info.ModTime()) < ouiMaxAge {
		if db, err := parseOUIFile(path); err == nil {
			return db
		}
	}

	// Download fresh copy.
	if err := downloadOUI(path); err == nil {
		if db, err := parseOUIFile(path); err == nil {
			return db
		}
	}

	// Fall back to stale cache if download failed.
	db, _ := parseOUIFile(path)
	return db
}

func ouiCachePath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".cache", "net-sweep", "oui.txt")
}

func downloadOUI(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(ouiURL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	tmp, err := os.CreateTemp(filepath.Dir(path), "oui-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)

	if _, err := io.Copy(tmp, resp.Body); err != nil {
		tmp.Close()
		return err
	}
	tmp.Close()

	return os.Rename(tmpPath, path)
}

// parseOUIFile parses the IEEE oui.txt format.
// Relevant lines look like: "00-00-00   (hex)\t\tVENDOR NAME"
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
		prefix := strings.ToUpper(strings.TrimSpace(strings.Fields(parts[0])[0]))
		vendor := strings.TrimSpace(parts[1])
		if len(prefix) == 8 { // XX-XX-XX
			db[prefix] = vendor
		}
	}
	return db, scanner.Err()
}
