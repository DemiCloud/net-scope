package scan

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/gosnmp/gosnmp"
)

// Standard MIB-II OIDs for device identity.
var snmpOIDs = []string{
	"1.3.6.1.2.1.1.1.0", // sysDescr    — model, firmware, OS details
	"1.3.6.1.2.1.1.5.0", // sysName     — configured hostname
	"1.3.6.1.2.1.1.6.0", // sysLocation — physical location string
	"1.3.6.1.2.1.1.4.0", // sysContact  — admin contact
}

// probeSNMP queries a host via SNMP v2c and returns identity info.
// Returns nil if the host doesn't respond or SNMP isn't available.
func probeSNMP(ctx context.Context, ip net.IP, community string, timeout time.Duration) *SNMPInfo {
	g := &gosnmp.GoSNMP{
		Context:   ctx,
		Target:    ip.String(),
		Port:      161,
		Community: community,
		Version:   gosnmp.Version2c,
		Timeout:   timeout,
		Retries:   0,
	}
	if err := g.Connect(); err != nil {
		return nil
	}
	defer g.Conn.Close()

	result, err := g.Get(snmpOIDs)
	if err != nil || result == nil {
		return nil
	}

	info := &SNMPInfo{}
	for _, v := range result.Variables {
		if v.Type == gosnmp.NoSuchObject || v.Type == gosnmp.NoSuchInstance {
			continue
		}
		val := snmpString(v)
		switch v.Name {
		case ".1.3.6.1.2.1.1.1.0":
			info.SysDescr = val
		case ".1.3.6.1.2.1.1.5.0":
			info.SysName = val
		case ".1.3.6.1.2.1.1.6.0":
			info.SysLocation = val
		case ".1.3.6.1.2.1.1.4.0":
			info.SysContact = val
		}
	}

	if info.SysDescr == "" && info.SysName == "" {
		return nil
	}
	return info
}

func snmpString(v gosnmp.SnmpPDU) string {
	switch v.Type {
	case gosnmp.OctetString:
		if b, ok := v.Value.([]byte); ok {
			return strings.TrimSpace(string(b))
		}
	case gosnmp.ObjectIdentifier:
		return fmt.Sprintf("%v", v.Value)
	}
	return fmt.Sprintf("%v", v.Value)
}
