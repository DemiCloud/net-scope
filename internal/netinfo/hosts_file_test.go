package netinfo

import (
	"os"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// hostsNamesMatch (package-internal)
// ---------------------------------------------------------------------------

func TestHostsNamesMatch_Equal(t *testing.T) {
	if !hostsNamesMatch([]string{"foo", "bar"}, []string{"foo", "bar"}) {
		t.Error("identical slices should match")
	}
}

func TestHostsNamesMatch_DifferentOrder(t *testing.T) {
	if !hostsNamesMatch([]string{"bar", "foo"}, []string{"foo", "bar"}) {
		t.Error("order-independent match should succeed")
	}
}

func TestHostsNamesMatch_CaseInsensitive(t *testing.T) {
	if !hostsNamesMatch([]string{"HOST.LOCAL"}, []string{"host.local"}) {
		t.Error("match should be case-insensitive")
	}
}

func TestHostsNamesMatch_DifferentLength(t *testing.T) {
	if hostsNamesMatch([]string{"foo"}, []string{"foo", "bar"}) {
		t.Error("different-length slices should not match")
	}
}

func TestHostsNamesMatch_DifferentValues(t *testing.T) {
	if hostsNamesMatch([]string{"foo"}, []string{"bar"}) {
		t.Error("different values should not match")
	}
}

func TestHostsNamesMatch_BothEmpty(t *testing.T) {
	if !hostsNamesMatch([]string{}, []string{}) {
		t.Error("two empty slices should match")
	}
}

// ---------------------------------------------------------------------------
// ReadHostsFile — smoke test on /etc/hosts (read-only, no system changes)
// ---------------------------------------------------------------------------

func TestReadHostsFile_ReturnsEntries(t *testing.T) {
	if _, err := os.Open("/etc/hosts"); err != nil {
		t.Skip("/etc/hosts not accessible:", err)
	}
	entries := ReadHostsFile()
	// Every real system should have at least one entry (e.g. 127.0.0.1 localhost).
	if len(entries) == 0 {
		t.Error("ReadHostsFile returned no entries from /etc/hosts")
	}
	// Each returned entry must have a non-empty IP and at least one hostname.
	for i, e := range entries {
		if e.IP == "" {
			t.Errorf("entry %d has empty IP", i)
		}
		if len(e.Hostnames) == 0 {
			t.Errorf("entry %d (IP %s) has no hostnames", i, e.IP)
		}
	}
}

func TestReadHostsFile_SkipsBlankAndCommentLines(t *testing.T) {
	if _, err := os.Open("/etc/hosts"); err != nil {
		t.Skip("/etc/hosts not accessible:", err)
	}
	entries := ReadHostsFile()
	for _, e := range entries {
		if strings.HasPrefix(strings.TrimSpace(e.IP), "#") {
			t.Errorf("comment line leaked through: IP=%q", e.IP)
		}
	}
}
