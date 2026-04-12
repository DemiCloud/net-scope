package probes

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"strings"
	"time"

	"github.com/demicloud/net-scope/internal/scan"
)

func registerGaming() {
	scan.RegisterDeepProbe(scan.DeepProbe{
		ID: "steam-a2s", Group: "Gaming / Media", Name: "Steam A2S Info",
		DefaultPort: 27015, Transport: "UDP", Run: probeSteamA2S,
	})
	scan.RegisterDeepProbe(scan.DeepProbe{
		ID: "minecraft", Group: "Gaming / Media", Name: "Minecraft Status",
		DefaultPort: 25565, Transport: "TCP", Run: probeMinecraft,
	})
	scan.RegisterDeepProbe(scan.DeepProbe{
		ID: "rtsp", Group: "Gaming / Media", Name: "RTSP OPTIONS",
		DefaultPort: 554, Transport: "TCP", Run: probeRTSP,
	})
}

// A2S_INFO request payload.
var a2sInfoRequest = []byte{
	0xFF, 0xFF, 0xFF, 0xFF, // header
	0x54,                   // T = A2S_INFO
	0x53, 0x6F, 0x75, 0x72, 0x63, 0x65, 0x20, 0x45, 0x6E, 0x67, 0x69, 0x6E, 0x65,
	0x20, 0x51, 0x75, 0x65, 0x72, 0x79, 0x00, // "Source Engine Query\0"
}

func probeSteamA2S(_ context.Context, ip string, port int, dial scan.DialFunc, emit func(string)) ([]scan.Observation, error) {
	emit(fmt.Sprintf("Sending A2S_INFO to %s…", joinHost(ip, port)))
	conn, err := dialUDP(ip, port, 5*time.Second)
	if err != nil {
		emit("Failed to open UDP socket: " + err.Error())
		return nil, nil
	}
	defer conn.Close()

	if _, err := conn.Write(a2sInfoRequest); err != nil {
		emit("Send failed: " + err.Error())
		return nil, nil
	}

	buf := make([]byte, 1400)
	n, err := conn.Read(buf)
	if err != nil || n < 6 {
		emit("No A2S_INFO response — not a Source engine server or firewall blocked")
		return nil, nil
	}

	// Response: 4-byte header (0xFFFFFFFF) + 0x49 (INFO) + payload.
	if buf[4] != 0x49 {
		emit(fmt.Sprintf("Unexpected response byte: 0x%02X (expected 0x49 for A2S_INFO)", buf[4]))
		return nil, nil
	}

	// Parse null-terminated strings: protocol, name, map, folder, game.
	_ = buf[5] // protocol version
	off := 6
	readStr := func() string {
		end := off
		for end < n && buf[end] != 0 {
			end++
		}
		s := string(buf[off:end])
		if end < n {
			off = end + 1
		} else {
			off = end
		}
		return s
	}
	name := readStr()
	mapName := readStr()
	_ = readStr() // folder
	game := readStr()

	var result []scan.Observation
	emit("Server name:  " + name)
	emit("Map:          " + mapName)
	emit("Game:         " + game)

	result = append(result, obs("probe", "steam_name", name))
	result = append(result, obs("probe", "steam_map", mapName))
	result = append(result, obs("probe", "steam_game", game))

	if off+4 <= n {
		players := int(buf[off])
		maxPlayers := int(buf[off+1])
		bots := int(buf[off+2])
		emit(fmt.Sprintf("Players:      %d / %d (%d bots)", players, maxPlayers, bots))
		result = append(result, obs("probe", "steam_players", fmt.Sprintf("%d/%d", players, maxPlayers)))
	}
	return result, nil
}

// probeMinecraft uses the Minecraft 1.7+ Server List Ping protocol.
func probeMinecraft(_ context.Context, ip string, port int, dial scan.DialFunc, emit func(string)) ([]scan.Observation, error) {
	emit(fmt.Sprintf("Connecting to %s (Minecraft)…", joinHost(ip, port)))
	conn, err := dialTCP(context.Background(), dial, ip, port, 5*time.Second)
	if err != nil {
		emit("Connection failed: " + err.Error())
		return nil, nil
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second)) //nolint:errcheck

	// Build Handshake packet (id=0x00) + Status request (id=0x00).
	// VarInt encoding: each byte has MSB as continuation bit.
	hostBytes := []byte(ip)
	hostLen := varInt(len(hostBytes))

	handshakeData := []byte{0x00} // packet ID 0x00
	handshakeData = append(handshakeData, 0x00) // protocol version = 0 (ping only)
	handshakeData = append(handshakeData, hostLen...)
	handshakeData = append(handshakeData, hostBytes...)
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(port))
	handshakeData = append(handshakeData, portBytes...)
	handshakeData = append(handshakeData, 0x01) // next state = 1 (status)

	pkt := append(varInt(len(handshakeData)), handshakeData...)
	statusReq := []byte{0x01, 0x00} // length=1, id=0x00

	emit("Sending Minecraft handshake + status request…")
	conn.Write(pkt)           //nolint:errcheck
	conn.Write(statusReq)     //nolint:errcheck

	// Read response: VarInt length, VarInt packet ID (0x00), VarInt string length, JSON.
	buf := make([]byte, 4096)
	n, _ := conn.Read(buf)
	if n < 3 {
		emit("No status response — server may not be Minecraft Java Edition")
		return nil, nil
	}

	// Find the JSON object (starts with '{') — skip VarInt prefixes.
	jsonStart := -1
	for i := 0; i < n; i++ {
		if buf[i] == '{' {
			jsonStart = i
			break
		}
	}
	if jsonStart < 0 {
		emit("Response received but no JSON payload found")
		return nil, nil
	}
	raw := string(buf[jsonStart:n])

	var result []scan.Observation
	emit("Got status JSON:")

	if v := jsonStr(raw, "name"); v != "" {
		emit("Version:      " + v)
		result = append(result, obs("probe", "version", v))
	}
	// MOTD is in "description" which may be a plain string or {"text":"..."}.
	if v := jsonStr(raw, "text"); v != "" {
		emit("MOTD:         " + stripMCFormatting(v))
		result = append(result, obs("probe", "mc_motd", stripMCFormatting(v)))
	} else if strings.Contains(raw, `"description"`) {
		// description is a plain string.
		if v := jsonStr(raw, "description"); v != "" {
			emit("MOTD:         " + stripMCFormatting(v))
			result = append(result, obs("probe", "mc_motd", stripMCFormatting(v)))
		}
	}
	if strings.Contains(raw, `"online"`) {
		online := jsonStr(raw, "online")
		max := jsonStr(raw, "max")
		emit(fmt.Sprintf("Players:      %s / %s", online, max))
		result = append(result, obs("probe", "mc_players", online+"/"+max))
	}
	return result, nil
}

// varInt encodes n as a Minecraft VarInt.
func varInt(n int) []byte {
	var buf []byte
	for {
		part := n & 0x7F
		n >>= 7
		if n != 0 {
			part |= 0x80
		}
		buf = append(buf, byte(part))
		if n == 0 {
			break
		}
	}
	return buf
}

// stripMCFormatting removes §X colour codes from a Minecraft string.
func stripMCFormatting(s string) string {
	var b strings.Builder
	runes := []rune(s)
	for i := 0; i < len(runes); i++ {
		if runes[i] == '§' && i+1 < len(runes) {
			i++ // skip format code character
			continue
		}
		b.WriteRune(runes[i])
	}
	return b.String()
}

func probeRTSP(_ context.Context, ip string, port int, dial scan.DialFunc, emit func(string)) ([]scan.Observation, error) {
	emit(fmt.Sprintf("Connecting to %s (RTSP)…", joinHost(ip, port)))
	conn, err := dialTCP(context.Background(), dial, ip, port, 5*time.Second)
	if err != nil {
		emit("Connection failed: " + err.Error())
		return nil, nil
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second)) //nolint:errcheck

	// RTSP OPTIONS request (RFC 2326/7826).
	req := fmt.Sprintf(
		"OPTIONS rtsp://%s/ RTSP/1.0\r\n"+
			"CSeq: 1\r\n"+
			"User-Agent: NetScope\r\n"+
			"\r\n",
		joinHost(ip, port))
	emit("Sending OPTIONS request…")
	if _, err := fmt.Fprint(conn, req); err != nil {
		emit("Write failed: " + err.Error())
		return nil, nil
	}

	sc := bufio.NewScanner(conn)
	var result []scan.Observation
	for sc.Scan() {
		l := sc.Text()
		if l == "" {
			break
		}
		lower := toLower(l)
		if strings.HasPrefix(lower, "rtsp/") {
			emit("Status: " + l)
			result = append(result, obs("probe", "rtsp_status", l))
		} else if strings.HasPrefix(lower, "server:") {
			s := strings.TrimSpace(l[7:])
			emit("Server:  " + s)
			result = append(result, obs("probe", "rtsp_server", s))
		} else if strings.HasPrefix(lower, "public:") {
			methods := strings.TrimSpace(l[7:])
			emit("Methods: " + methods)
			result = append(result, obs("probe", "rtsp_methods", methods))
		} else if strings.HasPrefix(lower, "content-base:") || strings.HasPrefix(lower, "cseq:") {
			// informational, skip
		}
	}
	if len(result) == 0 {
		emit("No RTSP OPTIONS response — may not be an RTSP server")
	}
	return result, nil
}
