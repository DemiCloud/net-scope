package probes

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/demicloud/net-scope/internal/scan"
)

func registerFileShare() {
	scan.RegisterDeepProbe(scan.DeepProbe{
		ID: "smb-deep", Group: "File / Share", Name: "SMB [Negotiate]",
		ServiceName: "File Server",
		DefaultPort: 445, Transport: "TCP", Run: probeSMBDeep,
	})
	scan.RegisterDeepProbe(scan.DeepProbe{
		ID: "ftp", Group: "File / Share", Name: "FTP [Banner]",
		ServiceName: "FTP Server",
		DefaultPort: 21, Transport: "TCP", Run: probeFTP,
	})
	scan.RegisterDeepProbe(scan.DeepProbe{
		ID: "ipp", Group: "File / Share", Name: "IPP [Attributes]",
		ServiceName: "Print Server",
		DefaultPort: 631, Transport: "TCP", Run: probeIPP,
	})
	scan.RegisterDeepProbe(scan.DeepProbe{
		ID: "pjl", Group: "File / Share", Name: "PJL [Info]",
		ServiceName: "Print Server",
		DefaultPort: 9100, Transport: "TCP", Run: probePJL,
	})
}

// SMBv2 NEGOTIATE request — identical to the one in internal/scan/svc_probes.go
// but reproduced here so this package has no dependency on unexported scan internals.
var smbv2Req = []byte{
	0x00, 0x00, 0x00, 0x6E,
	0xFE, 0x53, 0x4D, 0x42, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0xFF, 0xFE, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x24, 0x00, 0x05, 0x00, 0x01, 0x00,
	0x00, 0x00, 0x7F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x02, 0x10, 0x02,
	0x00, 0x03, 0x02, 0x03, 0x11, 0x03,
}

var smbv1Req = []byte{
	0x00, 0x00, 0x00, 0x2F,
	0xFF, 0x53, 0x4D, 0x42, 0x72, 0x00, 0x00, 0x00, 0x00, 0x18, 0x01, 0x28,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x2F, 0x4B, 0x00, 0x00, 0xC5, 0xE2,
	0x00, 0x0C, 0x00,
	0x02, 0x4E, 0x54, 0x20, 0x4C, 0x4D, 0x20, 0x30, 0x2E, 0x31, 0x32, 0x00,
}

func smbDialect(d uint16) string {
	switch d {
	case 0x0202:
		return "SMB 2.0.2"
	case 0x0210:
		return "SMB 2.1"
	case 0x0300:
		return "SMB 3.0"
	case 0x0302:
		return "SMB 3.0.2"
	case 0x0311:
		return "SMB 3.1.1"
	case 0x02FF:
		return "SMB 2.x"
	default:
		return fmt.Sprintf("SMB 0x%04X", d)
	}
}

func probeSMBDeep(_ context.Context, ip string, port int, dial scan.DialFunc, emit func(string)) ([]scan.Observation, error) {
	emit(fmt.Sprintf("Connecting to %s (SMB)…", joinHost(ip, port)))
	conn, err := dialTCP(context.Background(), dial, ip, port, 5*time.Second)
	if err != nil {
		emit("Connection failed: " + err.Error())
		return nil, nil
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second)) //nolint:errcheck

	emit("Sending SMBv2 NEGOTIATE…")
	if _, err := conn.Write(smbv2Req); err != nil {
		emit("Write failed: " + err.Error())
		return nil, nil
	}

	var nbHdr [4]byte
	if _, err := io.ReadFull(conn, nbHdr[:]); err != nil {
		emit("No response (not SMB or connection reset)")
		return nil, nil
	}
	msgLen := binary.BigEndian.Uint32(nbHdr[:]) & 0x00FFFFFF
	if msgLen < 70 || msgLen > 65535 {
		emit("Response length invalid — may not be an SMB server")
		return nil, nil
	}
	resp := make([]byte, msgLen)
	if _, err := io.ReadFull(conn, resp); err != nil {
		emit("Short read: " + err.Error())
		return nil, nil
	}
	if len(resp) < 70 || resp[0] != 0xFE || string(resp[1:4]) != "SMB" {
		emit("Response is not SMBv2 — may be SMBv1-only or non-SMB service")
		return nil, nil
	}

	dialect := binary.LittleEndian.Uint16(resp[68:70])
	dialectStr := smbDialect(dialect)
	emit("SMBv2 dialect:    " + dialectStr)

	secMode := resp[70] // SecurityMode byte: bit0 = SigningEnabled, bit1 = SigningRequired
	var result []scan.Observation
	result = append(result, obs("probe", "smb_dialect", dialectStr))
	signing := "optional"
	if secMode&0x02 != 0 {
		signing = "required"
	}
	emit("Signing:          " + signing)
	result = append(result, obs("probe", "smb_signing", signing))

	// Test SMBv1 on a separate connection.
	emit("Testing SMBv1 support…")
	conn2, err := dialTCP(context.Background(), dial, ip, port, 3*time.Second)
	smb1 := false
	if err == nil {
		conn2.SetDeadline(time.Now().Add(3 * time.Second)) //nolint:errcheck
		if _, err := conn2.Write(smbv1Req); err == nil {
			var hdr2 [4]byte
			if _, err := io.ReadFull(conn2, hdr2[:]); err == nil {
				l2 := binary.BigEndian.Uint32(hdr2[:]) & 0x00FFFFFF
				if l2 >= 4 {
					peek := make([]byte, 4)
					if _, err := io.ReadFull(conn2, peek); err == nil {
						smb1 = peek[0] == 0xFF && peek[1] == 'S' && peek[2] == 'M' && peek[3] == 'B'
					}
				}
			}
		}
		conn2.Close()
	}
	if smb1 {
		emit("⚠  SMBv1 ENABLED — vulnerable to EternalBlue / WannaCry-class exploits!")
		result = append(result, obs("probe", "smb1", "enabled"))
	} else {
		emit("SMBv1:            disabled ✓")
		result = append(result, obs("probe", "smb1", "disabled"))
	}
	return result, nil
}

func probeFTP(_ context.Context, ip string, port int, dial scan.DialFunc, emit func(string)) ([]scan.Observation, error) {
	emit(fmt.Sprintf("Connecting to %s (FTP)…", joinHost(ip, port)))
	conn, err := dialTCP(context.Background(), dial, ip, port, 5*time.Second)
	if err != nil {
		emit("Connection failed: " + err.Error())
		return nil, nil
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second)) //nolint:errcheck

	sc := bufio.NewScanner(conn)
	var bannerLines []string
	for sc.Scan() {
		l := sc.Text()
		bannerLines = append(bannerLines, l)
		emit(l)
		// Multi-line banner ends with "220 " (code + space).
		if len(l) >= 4 && l[3] == ' ' {
			break
		}
	}
	if len(bannerLines) == 0 {
		emit("No banner received")
		return nil, nil
	}

	var result []scan.Observation
	result = append(result, obs("probe", "ftp_banner", joinStrings(bannerLines, " ")))

	// Try anonymous login.
	fmt.Fprintf(conn, "USER anonymous\r\n") //nolint:errcheck
	sc.Scan()
	resp := sc.Text()
	emit("→ USER anonymous:  " + resp)
	if strings.HasPrefix(resp, "331") {
		fmt.Fprintf(conn, "PASS probe@probe.test\r\n") //nolint:errcheck
		sc.Scan()
		passResp := sc.Text()
		emit("→ PASS:           " + passResp)
		if strings.HasPrefix(passResp, "230") {
			emit("⚠  Anonymous login ALLOWED — check for exposed files!")
			result = append(result, obs("probe", "ftp_anon", "allowed"))
		} else {
			result = append(result, obs("probe", "ftp_anon", "denied"))
		}
	} else if strings.HasPrefix(resp, "530") {
		emit("Anonymous login denied")
		result = append(result, obs("probe", "ftp_anon", "denied"))
	}
	fmt.Fprintf(conn, "QUIT\r\n") //nolint:errcheck
	return result, nil
}

func probeIPP(_ context.Context, ip string, port int, dial scan.DialFunc, emit func(string)) ([]scan.Observation, error) {
	emit(fmt.Sprintf("Connecting to %s (IPP/HTTP)…", joinHost(ip, port)))
	conn, err := dialTCP(context.Background(), dial, ip, port, 5*time.Second)
	if err != nil {
		emit("Connection failed: " + err.Error())
		return nil, nil
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second)) //nolint:errcheck

	// IPP runs over HTTP on /ipp/print (or /).
	req := "GET / HTTP/1.0\r\nHost: " + joinHost(ip, port) + "\r\nUser-Agent: probe/1.0\r\nConnection: close\r\n\r\n"
	fmt.Fprint(conn, req) //nolint:errcheck

	sc := bufio.NewScanner(conn)
	var result []scan.Observation
	for sc.Scan() {
		l := sc.Text()
		if l == "" {
			break
		}
		lower := strings.ToLower(l)
		if strings.HasPrefix(lower, "server:") {
			s := strings.TrimSpace(l[7:])
			emit("Server: " + s)
			result = append(result, obs("probe", "ipp_server", s))
		} else if strings.HasPrefix(l, "HTTP/") {
			emit("Status: " + l)
			result = append(result, obs("probe", "ipp_status", l))
		}
	}
	if len(result) == 0 {
		emit("No meaningful HTTP response")
	}
	return result, nil
}

func probePJL(_ context.Context, ip string, port int, dial scan.DialFunc, emit func(string)) ([]scan.Observation, error) {
	emit(fmt.Sprintf("Connecting to %s (PJL/JetDirect)…", joinHost(ip, port)))
	conn, err := dialTCP(context.Background(), dial, ip, port, 5*time.Second)
	if err != nil {
		emit("Connection failed: " + err.Error())
		return nil, nil
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second)) //nolint:errcheck

	// PJL INFO ID query — universally supported by HP/Xerox/Ricoh.
	fmt.Fprintf(conn, "\x1B%%-12345X@PJL\r\n@PJL INFO ID\r\n\x1B%%-12345X") //nolint:errcheck
	emit("→ @PJL INFO ID")

	sc := bufio.NewScanner(conn)
	var result []scan.Observation
	for sc.Scan() {
		l := strings.TrimSpace(sc.Text())
		if l == "" || l == "@PJL INFO ID" {
			continue
		}
		emit("ID: " + l)
		result = append(result, obs("probe", "pjl_id", l))
		break
	}

	// Also query firmware version.
	conn.SetDeadline(time.Now().Add(3 * time.Second)) //nolint:errcheck
	fmt.Fprintf(conn, "\x1B%%-12345X@PJL\r\n@PJL INFO STATUS\r\n\x1B%%-12345X") //nolint:errcheck
	for sc.Scan() {
		l := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(l, "CODE=") || strings.HasPrefix(l, "DISPLAY=") {
			emit(l)
			result = append(result, obs("probe", "pjl_status", l))
		}
	}
	return result, nil
}
