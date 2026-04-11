//go:build windows

package scan

import (
	"fmt"
	"syscall"
	"unsafe"
)

var (
	dnsapiDLL                      = syscall.NewLazyDLL("dnsapi.dll")
	kernel32DLL                     = syscall.NewLazyDLL("kernel32.dll")
	procDnsGetCacheDataTable        = dnsapiDLL.NewProc("DnsGetCacheDataTable")
	procDnsFlushResolverCache       = dnsapiDLL.NewProc("DnsFlushResolverCache")
	procDnsFlushResolverCacheEntryW = dnsapiDLL.NewProc("DnsFlushResolverCacheEntry_W")
	procLocalFree                   = kernel32DLL.NewProc("LocalFree")
)

// dnsCacheEntryW mirrors the DNS_CACHE_ENTRY structure returned by
// DnsGetCacheDataTable on 64-bit Windows (24 bytes, natural alignment).
type dnsCacheEntryW struct {
	pNext       uintptr // pointer to the next entry
	pszName     uintptr // pointer to a UTF-16 null-terminated DNS name
	wType       uint16  // DNS record type (e.g. 1=A, 28=AAAA, 5=CNAME)
	wDataLength uint16
	dwFlags     uint32
}

var dnsRecordTypeNames = map[uint16]string{
	1:   "A",
	2:   "NS",
	5:   "CNAME",
	6:   "SOA",
	12:  "PTR",
	15:  "MX",
	16:  "TXT",
	28:  "AAAA",
	33:  "SRV",
	35:  "NAPTR",
	255: "ANY",
}

func dnsRecordTypeName(t uint16) string {
	if s, ok := dnsRecordTypeNames[t]; ok {
		return s
	}
	return fmt.Sprintf("TYPE%d", t)
}

// utf16PtrToString reads a null-terminated UTF-16 string from a raw pointer.
// Returns "" if ptr is 0.
func utf16PtrToString(ptr uintptr) string {
	if ptr == 0 {
		return ""
	}
	// Bound the read: DNS names are at most 253 characters.
	p := (*[512]uint16)(unsafe.Pointer(ptr))
	n := 0
	for n < len(p) && p[n] != 0 {
		n++
	}
	return syscall.UTF16ToString(p[:n])
}

// ReadDNSCache returns all entries currently in the Windows DNS resolver
// cache. Returns nil if the API is unavailable or the cache is empty.
// The cache is shared across all processes (maintained by the DNS Client
// service); no special privileges are required to read it.
func ReadDNSCache() []DNSCacheEntry {
	if err := procDnsGetCacheDataTable.Find(); err != nil {
		return nil
	}
	var pHead uintptr
	r, _, _ := procDnsGetCacheDataTable.Call(uintptr(unsafe.Pointer(&pHead)))
	if r == 0 || pHead == 0 {
		return nil
	}

	// Deduplicate (same name may appear once per record type).
	type key struct{ name, typ string }
	seen := map[key]struct{}{}
	var entries []DNSCacheEntry

	p := pHead
	for p != 0 {
		entry := (*dnsCacheEntryW)(unsafe.Pointer(p))
		name := utf16PtrToString(entry.pszName)
		typeName := dnsRecordTypeName(entry.wType)

		k := key{name, typeName}
		if _, dup := seen[k]; !dup {
			seen[k] = struct{}{}
			entries = append(entries, DNSCacheEntry{Name: name, Type: typeName})
		}

		// Free the name string, then advance and free the entry itself.
		if entry.pszName != 0 {
			procLocalFree.Call(entry.pszName)
		}
		next := entry.pNext
		procLocalFree.Call(p)
		p = next
	}
	return entries
}

// FlushDNSCache clears all entries from the Windows DNS resolver cache.
// On most configurations this does not require administrator privileges.
func FlushDNSCache() error {
	r, _, _ := procDnsFlushResolverCache.Call()
	if r == 0 {
		return fmt.Errorf("DnsFlushResolverCache failed (may require elevation)")
	}
	return nil
}

// DeleteDNSCacheEntry removes the resolver-cache entries for a single DNS
// name. Requires the DNS Client service to be running; usually does not
// require administrator privileges.
func DeleteDNSCacheEntry(name string) error {
	if err := procDnsFlushResolverCacheEntryW.Find(); err != nil {
		return fmt.Errorf("DnsFlushResolverCacheEntry_W not available: %w", err)
	}
	ptr, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return fmt.Errorf("invalid DNS name %q: %w", name, err)
	}
	r, _, lastErr := procDnsFlushResolverCacheEntryW.Call(uintptr(unsafe.Pointer(ptr)))
	if r == 0 {
		if lastErr != nil && lastErr != syscall.Errno(0) {
			return fmt.Errorf("DnsFlushResolverCacheEntry_W(%q): %w", name, lastErr)
		}
		return fmt.Errorf("DnsFlushResolverCacheEntry_W(%q) failed", name)
	}
	return nil
}
