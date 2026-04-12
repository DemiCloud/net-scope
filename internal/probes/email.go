package probes

import (
	"bufio"
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/demicloud/net-scope/internal/scan"
)

func registerEmail() {
	scan.RegisterDeepProbe(scan.DeepProbe{
		ID: "smtp-deep", Group: "Email", Name: "SMTP EHLO",
		DefaultPort: 25, Transport: "TCP", Run: probeSMTPDeep,
	})
	scan.RegisterDeepProbe(scan.DeepProbe{
		ID: "imap", Group: "Email", Name: "IMAP CAPABILITY",
		DefaultPort: 143, Transport: "TCP", Run: probeIMAP,
	})
	scan.RegisterDeepProbe(scan.DeepProbe{
		ID: "pop3", Group: "Email", Name: "POP3 CAPA",
		DefaultPort: 110, Transport: "TCP", Run: probePOP3,
	})
}

func probeSMTPDeep(_ context.Context, ip string, port int, dial scan.DialFunc, emit func(string)) ([]scan.Observation, error) {
	emit(fmt.Sprintf("Connecting to %s (SMTP)…", joinHost(ip, port)))
	conn, err := dialTCP(context.Background(), dial, ip, port, 5*time.Second)
	if err != nil {
		emit("Connection failed: " + err.Error())
		return nil, nil
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(8 * time.Second)) //nolint:errcheck

	sc := bufio.NewScanner(conn)
	// Read multi-line banner (220-... lines until 220 space line).
	var bannerLines []string
	for sc.Scan() {
		l := sc.Text()
		bannerLines = append(bannerLines, l)
		if strings.HasPrefix(l, "220 ") {
			break
		}
		if !strings.HasPrefix(l, "220-") {
			emit("Unexpected greeting: " + l)
			return nil, nil
		}
	}
	banner := strings.Join(bannerLines, "\n")
	emit("Banner: " + strings.TrimPrefix(bannerLines[0], "220 "))
	var result []scan.Observation
	result = append(result, obs("probe", "smtp_banner", strings.TrimPrefix(bannerLines[0], "220 ")))

	// Send EHLO.
	fmt.Fprintf(conn, "EHLO probe.test\r\n") //nolint:errcheck
	emit("→ EHLO probe.test")
	_ = banner

	var caps []string
	for sc.Scan() {
		l := sc.Text()
		if strings.HasPrefix(l, "250-") {
			caps = append(caps, strings.TrimPrefix(l, "250-"))
		} else if strings.HasPrefix(l, "250 ") {
			caps = append(caps, strings.TrimPrefix(l, "250 "))
			break
		} else {
			break
		}
	}
	starttls := false
	var authMethods []string
	for _, cap := range caps {
		emit("  " + cap)
		upper := strings.ToUpper(cap)
		if upper == "STARTTLS" {
			starttls = true
		}
		if strings.HasPrefix(upper, "AUTH ") {
			methods := strings.Fields(cap)[1:]
			authMethods = append(authMethods, methods...)
		}
	}
	result = append(result, obs("probe", "smtp_caps", joinStrings(caps, ", ")))
	if starttls {
		emit("STARTTLS: supported")
		result = append(result, obs("probe", "smtp_starttls", "supported"))
	} else {
		emit("⚠  STARTTLS not advertised — credentials sent in cleartext")
		result = append(result, obs("probe", "smtp_starttls", "unsupported"))
	}
	if len(authMethods) > 0 {
		authStr := joinStrings(authMethods, " ")
		emit("AUTH methods: " + authStr)
		result = append(result, obs("probe", "smtp_auth", authStr))
	}
	fmt.Fprintf(conn, "QUIT\r\n") //nolint:errcheck
	return result, nil
}

func probeIMAP(_ context.Context, ip string, port int, dial scan.DialFunc, emit func(string)) ([]scan.Observation, error) {
	emit(fmt.Sprintf("Connecting to %s (IMAP)…", joinHost(ip, port)))
	conn, err := dialTCP(context.Background(), dial, ip, port, 5*time.Second)
	if err != nil {
		emit("Connection failed: " + err.Error())
		return nil, nil
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(8 * time.Second)) //nolint:errcheck

	sc := bufio.NewScanner(conn)
	if !sc.Scan() {
		emit("No greeting received")
		return nil, nil
	}
	greeting := sc.Text()
	emit("Greeting: " + greeting)
	var result []scan.Observation
	if strings.Contains(greeting, "OK") {
		// Extract server name/software from greeting if present.
		parts := strings.SplitN(greeting, " ", 3)
		if len(parts) == 3 {
			result = append(result, obs("probe", "imap_banner", parts[2]))
		}
	}

	fmt.Fprintf(conn, "a1 CAPABILITY\r\n") //nolint:errcheck
	emit("→ a1 CAPABILITY")
	for sc.Scan() {
		l := sc.Text()
		if strings.HasPrefix(l, "* CAPABILITY") {
			caps := strings.TrimPrefix(l, "* CAPABILITY ")
			emit("Capabilities: " + caps)
			result = append(result, obs("probe", "imap_caps", caps))
			upper := strings.ToUpper(caps)
			if strings.Contains(upper, "STARTTLS") {
				emit("STARTTLS: supported")
				result = append(result, obs("probe", "imap_starttls", "supported"))
			} else {
				emit("⚠  STARTTLS not advertised")
				result = append(result, obs("probe", "imap_starttls", "unsupported"))
			}
		}
		if strings.HasPrefix(l, "a1 OK") || strings.HasPrefix(l, "a1 NO") || strings.HasPrefix(l, "a1 BAD") {
			break
		}
	}
	fmt.Fprintf(conn, "a2 LOGOUT\r\n") //nolint:errcheck
	return result, nil
}

func probePOP3(_ context.Context, ip string, port int, dial scan.DialFunc, emit func(string)) ([]scan.Observation, error) {
	emit(fmt.Sprintf("Connecting to %s (POP3)…", joinHost(ip, port)))
	conn, err := dialTCP(context.Background(), dial, ip, port, 5*time.Second)
	if err != nil {
		emit("Connection failed: " + err.Error())
		return nil, nil
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second)) //nolint:errcheck

	sc := bufio.NewScanner(conn)
	if !sc.Scan() {
		emit("No greeting received")
		return nil, nil
	}
	greeting := sc.Text()
	emit("Greeting: " + greeting)
	var result []scan.Observation
	result = append(result, obs("probe", "pop3_banner", strings.TrimPrefix(greeting, "+OK ")))

	fmt.Fprintf(conn, "CAPA\r\n") //nolint:errcheck
	emit("→ CAPA")
	var caps []string
	for sc.Scan() {
		l := sc.Text()
		if l == "." {
			break
		}
		if l == "-ERR" || strings.HasPrefix(l, "-ERR") {
			emit("CAPA not supported")
			break
		}
		caps = append(caps, l)
		emit("  " + l)
	}
	if len(caps) > 0 {
		result = append(result, obs("probe", "pop3_caps", joinStrings(caps, ", ")))
		hasSTLS := false
		for _, c := range caps {
			if strings.EqualFold(c, "STLS") {
				hasSTLS = true
				break
			}
		}
		if hasSTLS {
			emit("STLS (StartTLS): supported")
			result = append(result, obs("probe", "pop3_stls", "supported"))
		} else {
			emit("⚠  STLS not advertised — credentials sent in cleartext")
			result = append(result, obs("probe", "pop3_stls", "unsupported"))
		}
	}
	fmt.Fprintf(conn, "QUIT\r\n") //nolint:errcheck
	return result, nil
}
