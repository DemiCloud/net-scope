//go:build windows

package netinfo

import (
	"encoding/xml"
	"syscall"
	"time"
	"unsafe"
)

// ---------------------------------------------------------------------------
// wevtapi.dll bindings — Windows Event Log API (Vista+)
// ---------------------------------------------------------------------------

var (
	modWevtapi      = syscall.NewLazyDLL("wevtapi.dll")
	procEvtQuery    = modWevtapi.NewProc("EvtQuery")
	procEvtNext     = modWevtapi.NewProc("EvtNext")
	procEvtRender   = modWevtapi.NewProc("EvtRender")
	procEvtClose    = modWevtapi.NewProc("EvtClose")
)

// Flags for EvtQuery.
const (
	evtQueryChannelPath      uintptr = 0x1
	evtQueryReverseDirection uintptr = 0x200
)

// Flags for EvtRender.
const evtRenderEventXML uintptr = 1

// ERROR_NO_MORE_ITEMS from winerror.h.
const errNoMoreItems = 259

// ---------------------------------------------------------------------------
// Wire XML types for EvtRender output
// ---------------------------------------------------------------------------

type evtXML struct {
	XMLName  xml.Name  `xml:"Event"`
	System   evtSystem `xml:"System"`
	EventData struct {
		Data []struct {
			Name  string `xml:"Name,attr"`
			Value string `xml:",chardata"`
		} `xml:"Data"`
	} `xml:"EventData"`
}

type evtSystem struct {
	Provider struct {
		Name string `xml:"Name,attr"`
	} `xml:"Provider"`
	EventID     uint32 `xml:"EventID"`
	Level       uint8  `xml:"Level"`
	TimeCreated struct {
		SystemTime string `xml:"SystemTime,attr"`
	} `xml:"TimeCreated"`
	Channel string `xml:"Channel"`
}

// ---------------------------------------------------------------------------
// Summary lookup table for well-known network event IDs
// ---------------------------------------------------------------------------

// evtSummary maps provider name → event ID → short description.
var evtSummary = map[string]map[uint32]string{
	"Microsoft-Windows-Dhcp-Client": {
		1001: "DHCP: failed to obtain IP address (lease acquisition failed)",
		1002: "DHCP: failed to renew IP address lease",
		1003: "DHCP: IP address has been released",
		1025: "DHCP: failed to register with DNS",
	},
	"Microsoft-Windows-DNS-Client": {
		1014: "DNS: name resolution timed out",
		1015: "DNS: name resolution failure",
		8021: "DNS: cannot locate domain controller for domain",
		8022: "DNS: failed to connect to DNS server",
	},
	"NDIS": {
		10317: "NIC: link state changed (possible disconnect)",
		10319: "NIC: miniport reset event",
	},
	"Schannel": {
		36871: "TLS: fatal alert — handshake failure",
		36874: "TLS: connection to remote server closed unexpectedly",
		36887: "TLS: fatal alert received from remote server",
		36888: "TLS: fatal alert generated",
	},
	"Microsoft-Windows-Security-Auditing": {
		5152: "Firewall: packet dropped by Windows Filtering Platform",
	},
}

// evtLevel converts the numeric Windows event Level to a string.
func evtLevel(l uint8) string {
	switch l {
	case 1:
		return "Critical"
	case 2:
		return "Error"
	case 3:
		return "Warning"
	case 4:
		return "Information"
	case 5:
		return "Verbose"
	default:
		return "Unknown"
	}
}

// buildSummary returns a human-readable description for the event.
// Falls back to "Event <ID>" for unknown IDs.
func buildSummary(provider string, eventID uint32, data *evtXML) string {
	if m, ok := evtSummary[provider]; ok {
		if s, ok2 := m[eventID]; ok2 {
			// Append first non-empty EventData value for context.
			for _, d := range data.EventData.Data {
				if v := d.Value; v != "" {
					return s + " [" + v + "]"
				}
			}
			return s
		}
	}
	return "Event " + itoa(eventID)
}

// itoa is a minimal int-to-string helper to avoid importing fmt or strconv
// in this file (all other imports are already pulled in).
func itoa(n uint32) string {
	if n == 0 {
		return "0"
	}
	buf := [10]byte{}
	pos := len(buf)
	for n > 0 {
		pos--
		buf[pos] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[pos:])
}

// ---------------------------------------------------------------------------
// EvtQuery / EvtNext / EvtRender helpers
// ---------------------------------------------------------------------------

// evtQueryLog runs a single XPath query against a Windows event log channel
// and returns matching entries.
func evtQueryLog(channel, xpath string) []EventLogEntry {
	chW, _ := syscall.UTF16PtrFromString(channel)
	xpathW, _ := syscall.UTF16PtrFromString(xpath)

	hQuery, _, _ := procEvtQuery.Call(
		0, // local session
		uintptr(unsafe.Pointer(chW)),
		uintptr(unsafe.Pointer(xpathW)),
		evtQueryChannelPath|evtQueryReverseDirection,
	)
	if hQuery == 0 {
		return nil
	}
	defer procEvtClose.Call(hQuery)

	var entries []EventLogEntry
	var hEvent uintptr
	var returned uint32

	for {
		ret, _, lastErr := procEvtNext.Call(
			hQuery,
			1, // fetch one event at a time
			uintptr(unsafe.Pointer(&hEvent)),
			0,   // timeout = 0: return immediately
			0,   // flags
			uintptr(unsafe.Pointer(&returned)),
		)
		if ret == 0 {
			if lastErr == syscall.Errno(errNoMoreItems) {
				break
			}
			break
		}
		if returned == 0 {
			break
		}

		entry, ok := renderEvent(hEvent, channel)
		procEvtClose.Call(hEvent)
		if ok {
			entries = append(entries, entry)
		}
	}

	return entries
}

// renderEvent renders a single event handle to XML and parses it into an EventLogEntry.
func renderEvent(hEvent uintptr, channel string) (EventLogEntry, bool) {
	// First call: determine required buffer size.
	var used, propCount uint32
	procEvtRender.Call(
		0,
		hEvent,
		evtRenderEventXML,
		0, 0,
		uintptr(unsafe.Pointer(&used)),
		uintptr(unsafe.Pointer(&propCount)),
	)
	if used == 0 {
		return EventLogEntry{}, false
	}

	// Allocate a UTF-16 buffer of the reported size (in bytes → words).
	wordsNeeded := (int(used) + 1) / 2
	buf := make([]uint16, wordsNeeded+1)
	ret, _, _ := procEvtRender.Call(
		0,
		hEvent,
		evtRenderEventXML,
		uintptr(used),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&used)),
		uintptr(unsafe.Pointer(&propCount)),
	)
	if ret == 0 {
		return EventLogEntry{}, false
	}

	xmlStr := syscall.UTF16ToString(buf)
	var evt evtXML
	if err := xml.Unmarshal([]byte(xmlStr), &evt); err != nil {
		return EventLogEntry{}, false
	}

	provider := evt.System.Provider.Name
	eventID := evt.System.EventID

	// Parse the timestamp (Windows uses up to 7 decimal places: YYYY-MM-DDTHH:mm:ss.NNNNNNNZ).
	ts := evt.System.TimeCreated.SystemTime
	var t time.Time
	for _, layout := range []string{
		"2006-01-02T15:04:05.9999999Z",
		"2006-01-02T15:04:05Z",
		time.RFC3339Nano,
		time.RFC3339,
	} {
		if parsed, err := time.Parse(layout, ts); err == nil {
			t = parsed.UTC()
			break
		}
	}
	if t.IsZero() {
		t = time.Now().UTC()
	}

	logName := evt.System.Channel
	if logName == "" {
		logName = channel
	}

	return EventLogEntry{
		Time:    t.Format(time.RFC3339),
		Source:  provider,
		EventID: eventID,
		Log:     logName,
		Level:   evtLevel(evt.System.Level),
		Summary: buildSummary(provider, eventID, &evt),
	}, true
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

// networkLogQueries defines the channels and XPath filters queried by ReadNetworkEventLog.
var networkLogQueries = []struct {
	channel string
	xpath   string
}{
	{
		"System",
		`*[System[` +
			`(Provider[@Name='Microsoft-Windows-Dhcp-Client'] and (EventID=1001 or EventID=1002 or EventID=1003 or EventID=1025)) or ` +
			`(Provider[@Name='Microsoft-Windows-DNS-Client'] and (EventID=1014 or EventID=1015 or EventID=8021 or EventID=8022)) or ` +
			`(Provider[@Name='NDIS'] and (EventID=10317 or EventID=10319)) or ` +
			`(Provider[@Name='Schannel'] and (EventID=36871 or EventID=36874 or EventID=36887 or EventID=36888))` +
			`]]`,
	},
	{
		"Security",
		`*[System[EventID=5152]]`,
	},
}

// ReadNetworkEventLog queries the Windows Event Log for network-related events
// from the last maxHours hours, returning entries sorted newest-first.
// The Security log query may return no results when the service is not elevated
// or when audit policy for Filtering Platform Packet Drop is not enabled.
func ReadNetworkEventLog(maxHours int) []EventLogEntry {
	if maxHours <= 0 {
		maxHours = 24
	}
	cutoff := time.Now().UTC().Add(-time.Duration(maxHours) * time.Hour)
	cutoffStr := cutoff.Format("2006-01-02T15:04:05.0000000Z")

	var all []EventLogEntry
	for _, q := range networkLogQueries {
		// Prepend a time window filter.
		xpath := `*[System[TimeCreated[@SystemTime>='` + cutoffStr + `']]] and ` + q.xpath
		entries := evtQueryLog(q.channel, xpath)
		all = append(all, entries...)
	}

	// Sort newest-first (entries arrive reverse-chronological, but two channels
	// are interleaved so we need a proper sort).
	for i := 1; i < len(all); i++ {
		for j := i; j > 0 && all[j].Time > all[j-1].Time; j-- {
			all[j], all[j-1] = all[j-1], all[j]
		}
	}

	return all
}
