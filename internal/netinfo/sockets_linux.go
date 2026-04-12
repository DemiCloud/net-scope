//go:build linux

package netinfo

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// ReadSockets returns a point-in-time snapshot of all TCP and UDP sockets
// visible in /proc/net/{tcp,tcp6,udp,udp6}. PID and process-name lookup
// requires read access to /proc/[pid]/fd; those fields are left empty when
// access is denied (non-root).
func ReadSockets() []SocketEntry {
	imap := buildInodeMap()

	var out []SocketEntry
	out = append(out, parseProcNetSockets("TCP", "/proc/net/tcp", false, imap)...)
	out = append(out, parseProcNetSockets("TCP6", "/proc/net/tcp6", true, imap)...)
	out = append(out, parseProcNetSockets("UDP", "/proc/net/udp", false, imap)...)
	out = append(out, parseProcNetSockets("UDP6", "/proc/net/udp6", true, imap)...)
	return out
}

// linuxTCPStates maps /proc/net/tcp hex state codes to human-readable names.
var linuxTCPStates = map[uint8]string{
	0x01: "ESTABLISHED", 0x02: "SYN_SENT", 0x03: "SYN_RECV",
	0x04: "FIN_WAIT1", 0x05: "FIN_WAIT2", 0x06: "TIME_WAIT",
	0x07: "CLOSE", 0x08: "CLOSE_WAIT", 0x09: "LAST_ACK",
	0x0A: "LISTEN", 0x0B: "CLOSING",
}

func parseProcNetSockets(proto, path string, ipv6 bool, imap map[uint64]uint32) []SocketEntry {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	pidNames := map[uint32]string{}
	getName := func(pid uint32) string {
		if n, ok := pidNames[pid]; ok {
			return n
		}
		n := linuxProcessName(int(pid))
		pidNames[pid] = n
		return n
	}

	isTCP := strings.HasPrefix(proto, "TCP")

	var out []SocketEntry
	scanner := bufio.NewScanner(f)
	first := true
	for scanner.Scan() {
		if first {
			first = false
			continue // skip header
		}
		fields := strings.Fields(scanner.Text())
		// Fields: sl localAddr remAddr state txq rxq ... inode
		if len(fields) < 10 {
			continue
		}
		laddr, lport, err1 := parseHexAddr(fields[1], ipv6)
		raddr, rport, err2 := parseHexAddr(fields[2], ipv6)
		if err1 != nil || err2 != nil {
			continue
		}
		stateHex, _ := strconv.ParseUint(fields[3], 16, 8)
		state := ""
		if isTCP {
			state = linuxTCPStates[uint8(stateHex)]
		}
		inodeStr := fields[9]
		inode, _ := strconv.ParseUint(inodeStr, 10, 64)
		pid, hasPID := imap[inode]

		// For UDP and non-established TCP, remote may be 0.0.0.0:0 — normalise to "".
		if raddr == "0.0.0.0" || raddr == "::" {
			raddr = ""
			rport = 0
		}

		e := SocketEntry{
			Proto: proto, LocalAddr: laddr, LocalPort: lport,
			RemoteAddr: raddr, RemotePort: rport, State: state,
		}
		if hasPID {
			e.PID = pid
			e.Process = getName(pid)
		}
		out = append(out, e)
	}
	return out
}

// parseHexAddr parses "HHHHHHHH:PPPP" (IPv4) or "HHHHH...32:PPPP" (IPv6).
// Port is always in big-endian hex = direct value.
func parseHexAddr(s string, ipv6 bool) (string, uint16, error) {
	idx := strings.LastIndexByte(s, ':')
	if idx < 0 {
		return "", 0, fmt.Errorf("bad addr %q", s)
	}
	addrHex := s[:idx]
	portHex := s[idx+1:]

	port64, err := strconv.ParseUint(portHex, 16, 16)
	if err != nil {
		return "", 0, err
	}

	var ip net.IP
	if ipv6 {
		ip, err = decodeHexIPv6LE(addrHex)
	} else {
		var s string
		s, err = decodeHexIPLE(addrHex)
		if err == nil {
			ip = net.ParseIP(s).To4()
		}
	}
	if err != nil || ip == nil {
		return "", 0, fmt.Errorf("bad ip %q: %v", addrHex, err)
	}
	return ip.String(), uint16(port64), nil
}

// decodeHexIPv6LE decodes a 32-char hex string where each 4-byte group is
// stored in host byte order (little-endian on x86) into a net.IP.
// E.g. "00000000000000000000000001000000" → "::1".
func decodeHexIPv6LE(s string) (net.IP, error) {
	if len(s) != 32 {
		return nil, fmt.Errorf("expected 32 hex chars, got %d", len(s))
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}
	// Each 4-byte group is stored little-endian; reverse each group to get
	// network (big-endian) byte order.
	ip := make(net.IP, 16)
	for i := 0; i < 4; i++ {
		ip[i*4+0] = b[i*4+3]
		ip[i*4+1] = b[i*4+2]
		ip[i*4+2] = b[i*4+1]
		ip[i*4+3] = b[i*4+0]
	}
	return ip, nil
}

// buildInodeMap walks /proc/[pid]/fd looking for "socket:[inode]" symlinks and
// returns a map from socket inode to PID. Returns an empty map when access is
// denied (non-root).
func buildInodeMap() map[uint64]uint32 {
	result := map[uint64]uint32{}
	fdDirs, _ := filepath.Glob("/proc/[0-9]*/fd")
	for _, fdDir := range fdDirs {
		// Extract PID from /proc/PID/fd
		parts := strings.Split(fdDir, "/")
		if len(parts) < 3 {
			continue
		}
		pid64, err := strconv.ParseUint(parts[2], 10, 32)
		if err != nil {
			continue
		}
		pid := uint32(pid64)
		links, _ := filepath.Glob(fdDir + "/*")
		for _, link := range links {
			target, err := os.Readlink(link)
			if err != nil {
				continue
			}
			if !strings.HasPrefix(target, "socket:[") || !strings.HasSuffix(target, "]") {
				continue
			}
			inodeStr := target[8 : len(target)-1]
			inode, err := strconv.ParseUint(inodeStr, 10, 64)
			if err != nil {
				continue
			}
			if _, exists := result[inode]; !exists {
				result[inode] = pid
			}
		}
	}
	return result
}

// linuxProcessName reads /proc/[pid]/comm for the process name.
func linuxProcessName(pid int) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err != nil {
		return fmt.Sprintf("[%d]", pid)
	}
	return strings.TrimSpace(string(data))
}
