package probes

import (
	"context"
	"fmt"
	"time"

	"github.com/demicloud/net-scope/internal/scan"
)

func registerIndustrial() {
	scan.RegisterDeepProbe(scan.DeepProbe{
		ID: "modbus", Group: "Industrial / OT", Name: "Modbus MEI Device ID",
		DefaultPort: 502, Transport: "TCP", Run: probeModbus,
	})
	scan.RegisterDeepProbe(scan.DeepProbe{
		ID: "bacnet", Group: "Industrial / OT", Name: "BACnet Who-Is",
		DefaultPort: 47808, Transport: "UDP", Run: probeBACnet,
	})
}

// Modbus TCP MEI (Read Device Identification), function code 0x2B, sub 0x0E.
// Read Objects 0x00 (VendorName), 0x01 (ProductCode), 0x02 (MajorMinorRevision).
var modbusRequest = []byte{
	0x00, 0x01, // Transaction ID
	0x00, 0x00, // Protocol ID (Modbus = 0)
	0x00, 0x05, // Length = 5 bytes follow
	0x01,       // Unit ID
	0x2B,       // Function code: Read Device Identification (MEI)
	0x0E,       // MEI type: Read Device Identification
	0x01,       // ReadDevId code: stream (basic)
	0x00,       // Object ID: first (VendorName)
}

func probeModbus(_ context.Context, ip string, port int, dial scan.DialFunc, emit func(string)) ([]scan.Observation, error) {
	emit(fmt.Sprintf("Connecting to %s (Modbus TCP)…", joinHost(ip, port)))
	conn, err := dialTCP(context.Background(), dial, ip, port, 5*time.Second)
	if err != nil {
		emit("Connection failed: " + err.Error())
		return nil, nil
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second)) //nolint:errcheck

	emit("Sending MEI Read Device Identification request…")
	if _, err := conn.Write(modbusRequest); err != nil {
		emit("Write failed: " + err.Error())
		return nil, nil
	}

	buf := make([]byte, 256)
	n, _ := conn.Read(buf)
	if n < 8 {
		emit("No Modbus response — server may be offline or not Modbus TCP")
		return nil, nil
	}

	// Modbus TCP response header: 6 bytes (TxID, ProtID, Length, UnitID).
	fc := buf[7] // Function Code (or error code if 0x80 set).
	if fc&0x80 != 0 {
		emit(fmt.Sprintf("Modbus exception: function 0x%02X, exception code 0x%02X", fc&0x7F, buf[8]))
		return nil, nil
	}
	if fc != 0x2B {
		emit(fmt.Sprintf("Unexpected function code in response: 0x%02X", fc))
		return nil, nil
	}
	emit("Got MEI Device Identification response")

	var result []scan.Observation
	// Parse objects starting at offset 14 (after the MEI header).
	off := 14
	objNames := map[byte]string{
		0x00: "Vendor",
		0x01: "Product",
		0x02: "Version",
		0x03: "VendorURL",
		0x04: "ProductName",
		0x05: "ModelName",
		0x06: "UserApplicationName",
	}
	for off+2 <= n {
		objID := buf[off]
		objLen := int(buf[off+1])
		off += 2
		if off+objLen > n {
			break
		}
		val := string(buf[off : off+objLen])
		off += objLen

		label, ok := objNames[objID]
		if !ok {
			label = fmt.Sprintf("Object_%02X", objID)
		}
		emit(fmt.Sprintf("%-22s %s", label+":", val))
		result = append(result, obs("probe", "modbus_"+label, val))
	}
	if len(result) > 0 {
		emit("⚠  Modbus device responded — OT/ICS device exposed on the network!")
	}
	return result, nil
}

// BACnet Who-Is broadcast (IEC 62443 area) — sends to the individual host.
// BVLC-encapsulated BACnet/IP Who-Is service.
var bacnetWhoIs = []byte{
	0x81,       // BVLC type: BACnet/IP
	0x0A,       // Function: Original-Unicast-NPDU
	0x00, 0x0C, // BVLC length = 12
	// NPCI (Network Layer)
	0x01, 0x20, // Version 1, Priority: normal, expecting reply
	0xFF, 0xFF, // DADR: broadcast
	0x00, 0x00, // Hop count + padding
	// APDU: Unconfirmed-Request, Who-Is
	0x10, 0x08,
}

func probeBACnet(_ context.Context, ip string, port int, dial scan.DialFunc, emit func(string)) ([]scan.Observation, error) {
	emit(fmt.Sprintf("Sending BACnet Who-Is to %s…", joinHost(ip, port)))
	conn, err := dialUDP(ip, port, 5*time.Second)
	if err != nil {
		emit("Failed to open UDP socket: " + err.Error())
		return nil, nil
	}
	defer conn.Close()

	if _, err := conn.Write(bacnetWhoIs); err != nil {
		emit("Send failed: " + err.Error())
		return nil, nil
	}

	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil || n < 6 {
		emit("No BACnet response — device may be offline or not responding to unicast Who-Is")
		return nil, nil
	}
	emit("Got BACnet response")

	var result []scan.Observation
	// Check BVLC header.
	if buf[0] != 0x81 {
		emit(fmt.Sprintf("Unexpected response (BVLC type 0x%02X)", buf[0]))
		return nil, nil
	}
	emit("⚠  BACnet device is responding — building automation system exposed!")
	result = append(result, obs("probe", "bacnet_found", "true"))

	// Try to extract the I-Am service if present (APDU service choice 0x00 = I-Am).
	apduOffset := 6 // after BVLC + NPCI (varies; 6 is typical for simple unicast)
	for apduOffset < n-2 {
		if buf[apduOffset] == 0x10 && apduOffset+1 < n && buf[apduOffset+1] == 0x00 {
			// I-Am found — BACnet Object Identifier follows as a 4-byte tagged value.
			emit("I-Am service found in response")
			if apduOffset+7 <= n {
				// Extract device instance from Object Identifier (bits 21-0).
				raw := (uint32(buf[apduOffset+3])<<24 | uint32(buf[apduOffset+4])<<16 |
					uint32(buf[apduOffset+5])<<8 | uint32(buf[apduOffset+6])) & 0x3FFFFF
				emit(fmt.Sprintf("Device instance: %d", raw))
				result = append(result, obs("probe", "bacnet_device_id", fmt.Sprintf("%d", raw)))
			}
			break
		}
		apduOffset++
	}
	return result, nil
}
