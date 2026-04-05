// gen-rsrc generates cmd/gui-win/resource_windows_amd64.syso containing a
// VERSIONINFO resource (File Description, Company, Version shown in Explorer).
// Run via: go run ./cmd/gen-rsrc/ -dir cmd/gui-win
//
// The output is a minimal COFF object file (.syso). Go's linker automatically
// includes any *.syso file it finds in the package directory, no CGo needed.
package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
)

// ---------------------------------------------------------------------------
// JSON schema (matches cmd/gui-win/versioninfo.json)
// ---------------------------------------------------------------------------

type versionJSON struct {
	FixedFileInfo struct {
		FileVersion    versionNum `json:"FileVersion"`
		ProductVersion versionNum `json:"ProductVersion"`
	} `json:"FixedFileInfo"`
	StringFileInfo struct {
		CompanyName      string `json:"CompanyName"`
		FileDescription  string `json:"FileDescription"`
		FileVersion      string `json:"FileVersion"`
		InternalName     string `json:"InternalName"`
		LegalCopyright   string `json:"LegalCopyright"`
		OriginalFilename string `json:"OriginalFilename"`
		ProductName      string `json:"ProductName"`
		ProductVersion   string `json:"ProductVersion"`
	} `json:"StringFileInfo"`
}

type versionNum struct {
	Major, Minor, Patch, Build uint16
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

func main() {
	dir := flag.String("dir", ".", "directory containing versioninfo.json; .syso written there too")
	flag.Parse()

	raw, err := os.ReadFile(filepath.Join(*dir, "versioninfo.json"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "gen-rsrc:", err)
		os.Exit(1)
	}
	var info versionJSON
	if err := json.Unmarshal(raw, &info); err != nil {
		fmt.Fprintln(os.Stderr, "gen-rsrc: parse versioninfo.json:", err)
		os.Exit(1)
	}

	viData := buildVSVersionInfo(info)
	syso := buildCOFF(viData, []byte(appManifest))

	outPath := filepath.Join(*dir, "resource_windows_amd64.syso")
	if err := os.WriteFile(outPath, syso, 0644); err != nil {
		fmt.Fprintln(os.Stderr, "gen-rsrc:", err)
		os.Exit(1)
	}
	fmt.Printf("gen-rsrc: wrote %s (%d bytes, vi=%d bytes, manifest=%d bytes)\n",
		outPath, len(syso), len(viData), len(appManifest))
}

// ---------------------------------------------------------------------------
// VS_VERSIONINFO builder
// ---------------------------------------------------------------------------

func hiLo(hi, lo uint16) uint32 { return uint32(hi)<<16 | uint32(lo) }

func buildVSVersionInfo(info versionJSON) []byte {
	fv := info.FixedFileInfo.FileVersion
	pv := info.FixedFileInfo.ProductVersion

	// VS_FIXEDFILEINFO (52 bytes, binary, magic 0xFEEF04BD)
	fixed := make([]byte, 52)
	le := binary.LittleEndian
	le.PutUint32(fixed[0:], 0xFEEF04BD)                        // dwSignature
	le.PutUint32(fixed[4:], 0x00010000)                        // dwStrucVersion
	le.PutUint32(fixed[8:], hiLo(fv.Major, fv.Minor))          // dwFileVersionMS
	le.PutUint32(fixed[12:], hiLo(fv.Patch, fv.Build))         // dwFileVersionLS
	le.PutUint32(fixed[16:], hiLo(pv.Major, pv.Minor))         // dwProductVersionMS
	le.PutUint32(fixed[20:], hiLo(pv.Patch, pv.Build))         // dwProductVersionLS
	le.PutUint32(fixed[24:], 0x3F)                             // dwFileFlagsMask
	le.PutUint32(fixed[28:], 0x00)                             // dwFileFlags
	le.PutUint32(fixed[32:], 0x00040004)                       // dwFileOS  (VOS__WINDOWS32)
	le.PutUint32(fixed[36:], 0x00000001)                       // dwFileType (VFT_APP)
	le.PutUint32(fixed[40:], 0x00000000)                       // dwFileSubtype

	si := info.StringFileInfo
	stringPairs := [][2]string{
		{"CompanyName", si.CompanyName},
		{"FileDescription", si.FileDescription},
		{"FileVersion", si.FileVersion},
		{"InternalName", si.InternalName},
		{"LegalCopyright", si.LegalCopyright},
		{"OriginalFilename", si.OriginalFilename},
		{"ProductName", si.ProductName},
		{"ProductVersion", si.ProductVersion},
	}

	var strNodes [][]byte
	for _, kv := range stringPairs {
		if kv[1] != "" {
			strNodes = append(strNodes, makeStringLeaf(kv[0], kv[1]))
		}
	}

	strTable := makeVSNode(1, "040904B0", nil, strNodes...)
	strFileInfo := makeVSNode(1, "StringFileInfo", nil, strTable)

	transData := make([]byte, 4)
	binary.LittleEndian.PutUint32(transData, 0x04B00409) // English/Unicode
	transNode := makeVSNodeBin("Translation", transData)
	varFileInfo := makeVSNode(1, "VarFileInfo", nil, transNode)

	return makeVSNode(0, "VS_VERSION_INFO", fixed, strFileInfo, varFileInfo)
}

// utf16le encodes s as little-endian UTF-16 with a null terminator.
func utf16le(s string) []byte {
	var b bytes.Buffer
	for _, r := range s {
		var u [2]byte
		binary.LittleEndian.PutUint16(u[:], uint16(r))
		b.Write(u[:])
	}
	b.Write([]byte{0, 0})
	return b.Bytes()
}

func align4(n int) int { return (n + 3) &^ 3 }

// makeVSNode builds a VS_VERSIONINFO structure node (type = 0 binary or 1 text).
// wValueLength is set to len(value); for text nodes with no value, pass nil.
func makeVSNode(typ uint16, key string, value []byte, children ...[]byte) []byte {
	keyBytes := utf16le(key)
	var buf bytes.Buffer

	buf.Write(make([]byte, 6)) // header placeholder
	buf.Write(keyBytes)
	for buf.Len()%4 != 0 { // pad after key to DWORD boundary
		buf.WriteByte(0)
	}
	buf.Write(value)
	for len(value) > 0 && buf.Len()%4 != 0 { // pad after value
		buf.WriteByte(0)
	}
	for _, c := range children {
		buf.Write(c)
	}

	data := buf.Bytes()
	binary.LittleEndian.PutUint16(data[0:], uint16(len(data)))
	binary.LittleEndian.PutUint16(data[2:], uint16(len(value)))
	binary.LittleEndian.PutUint16(data[4:], typ)
	return data
}

// makeVSNodeBin is like makeVSNode but for binary children (VarFileInfo values).
func makeVSNodeBin(key string, value []byte) []byte {
	return makeVSNode(0, key, value)
}

// makeStringLeaf builds a String leaf node; wValueLength is in WCHARs (type=1).
func makeStringLeaf(key, value string) []byte {
	keyBytes := utf16le(key)
	valBytes := utf16le(value)
	valLenWCHARs := uint16(len(value) + 1) // chars including null terminator

	var buf bytes.Buffer
	buf.Write(make([]byte, 6))
	buf.Write(keyBytes)
	for buf.Len()%4 != 0 {
		buf.WriteByte(0)
	}
	buf.Write(valBytes)
	for buf.Len()%4 != 0 {
		buf.WriteByte(0)
	}

	data := buf.Bytes()
	binary.LittleEndian.PutUint16(data[0:], uint16(len(data)))
	binary.LittleEndian.PutUint16(data[2:], valLenWCHARs)
	binary.LittleEndian.PutUint16(data[4:], 1) // type = text
	return data
}

// ---------------------------------------------------------------------------
// Application manifest (enables comctl32 v6 visual styles on all controls)
// ---------------------------------------------------------------------------

const appManifest = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <assemblyIdentity type="win32" name="demicloud.net-sweep" version="1.0.0.0"
    processorArchitecture="amd64"/>
  <dependency>
    <dependentAssembly>
      <assemblyIdentity type="win32"
        name="Microsoft.Windows.Common-Controls"
        version="6.0.0.0"
        processorArchitecture="*"
        publicKeyToken="6595b64144ccf1df"
        language="*"/>
    </dependentAssembly>
  </dependency>
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level="asInvoker" uiAccess="false"/>
      </requestedPrivileges>
    </security>
  </trustInfo>
  <application xmlns="urn:schemas-microsoft-com:asm.v3">
    <windowsSettings>
      <dpiAwareness xmlns="http://schemas.microsoft.com/SMI/2016/WindowsSettings">PerMonitorV2</dpiAwareness>
    </windowsSettings>
  </application>
</assembly>
`

// ---------------------------------------------------------------------------
// COFF .syso builder
// ---------------------------------------------------------------------------

const (
	imageMachineAMD64          = uint16(0x8664)
	imageSCNInitializedData    = uint32(0x00000040)
	imageSCNAlign4Bytes        = uint32(0x00300000)
	imageSCNMemRead            = uint32(0x40000000)
	imageRelAMD64Addr32NB      = uint16(0x0003)
	imageSymClassStatic        = byte(3)

	rsrcCharacteristics = imageSCNInitializedData | imageSCNAlign4Bytes | imageSCNMemRead
)

// buildCOFF wraps viData and manifestData inside a minimal COFF object file
// (.syso) that the Go linker includes automatically.  The single .rsrc section
// holds two resource trees:
//
//   RT_VERSION  (type=16)  — VERSIONINFO displayed in Explorer
//   RT_MANIFEST (type=24)  — enables comctl32 v6 visual styles
//
// Section layout (all offsets relative to section start):
//
//   0   L1 dir           (16) — 2 ID entries
//   16  L1 entry type=16 ( 8) → L2-A at 32
//   24  L1 entry type=24 ( 8) → L2-B at 56
//   32  L2-A dir         (16) — 1 ID entry
//   48  L2-A entry id=1  ( 8) → L3-A at 80
//   56  L2-B dir         (16) — 1 ID entry
//   72  L2-B entry id=1  ( 8) → L3-B at 104
//   80  L3-A dir         (16) — 1 ID entry
//   96  L3-A entry 0409  ( 8) → DataEntry-A at 128
//  104  L3-B dir         (16) — 1 ID entry
//  120  L3-B entry 0409  ( 8) → DataEntry-B at 144
//  128  DataEntry-A      (16) — viData (ADDR32NB reloc patches OffsetToData)
//  144  DataEntry-B      (16) — manifestData (ditto)
//  160  viData (padded to DWORD)
//  160+viPad  manifestData (padded to DWORD)
func buildCOFF(viData []byte, manifestData []byte) []byte {
	viPadded := make([]byte, align4(len(viData)))
	copy(viPadded, viData)
	mfPadded := make([]byte, align4(len(manifestData)))
	copy(mfPadded, manifestData)

	const (
		offL1   = 0
		offL2A  = 32
		offL2B  = 56
		offL3A  = 80
		offL3B  = 104
		offDEA  = 128
		offDEB  = 144
		offData = 160
	)
	offManifest := offData + len(viPadded)
	sectionSize := offManifest + len(mfPadded)
	sec := make([]byte, sectionSize)

	putDir := func(off int, numID uint16) {
		binary.LittleEndian.PutUint16(sec[off+12:], 0)
		binary.LittleEndian.PutUint16(sec[off+14:], numID)
	}
	putEntry := func(off int, id, target uint32, isDir bool) {
		binary.LittleEndian.PutUint32(sec[off:], id)
		if isDir {
			binary.LittleEndian.PutUint32(sec[off+4:], 0x80000000|target)
		} else {
			binary.LittleEndian.PutUint32(sec[off+4:], target)
		}
	}

	// Level 1: two ID entries, sorted ascending (16 < 24)
	putDir(offL1, 2)
	putEntry(offL1+16, 16, uint32(offL2A), true) // RT_VERSION  = 16
	putEntry(offL1+24, 24, uint32(offL2B), true) // RT_MANIFEST = 24

	// Level 2-A: RT_VERSION subtree
	putDir(offL2A, 1)
	putEntry(offL2A+16, 1, uint32(offL3A), true)

	// Level 2-B: RT_MANIFEST subtree
	putDir(offL2B, 1)
	putEntry(offL2B+16, 1, uint32(offL3B), true)

	// Level 3-A: English (0x0409) → DataEntry-A
	putDir(offL3A, 1)
	putEntry(offL3A+16, 0x0409, uint32(offDEA), false)

	// Level 3-B: English (0x0409) → DataEntry-B
	putDir(offL3B, 1)
	putEntry(offL3B+16, 0x0409, uint32(offDEB), false)

	// DataEntry-A: viData
	le := binary.LittleEndian
	le.PutUint32(sec[offDEA:], uint32(offData))       // OffsetToData (ADDR32NB relocation addend)
	le.PutUint32(sec[offDEA+4:], uint32(len(viData))) // Size

	// DataEntry-B: manifest
	le.PutUint32(sec[offDEB:], uint32(offManifest))         // OffsetToData (ADDR32NB relocation addend)
	le.PutUint32(sec[offDEB+4:], uint32(len(manifestData))) // Size

	copy(sec[offData:], viPadded)
	copy(sec[offManifest:], mfPadded)

	const (
		coffHdrSize  = 20
		sectHdrSize  = 40
		relocSize    = 10
		numRelocs    = 2 // one per DataEntry
		symEntrySize = 18
		numSyms      = 2 // section symbol + aux record
		strTabSize   = 4
	)
	secDataOff := coffHdrSize + sectHdrSize
	relocOff := secDataOff + sectionSize
	symTabOff := relocOff + numRelocs*relocSize

	var out bytes.Buffer
	w := &out

	// ---- COFF header ----
	binary.Write(w, binary.LittleEndian, imageMachineAMD64)
	binary.Write(w, binary.LittleEndian, uint16(1))          // NumberOfSections
	binary.Write(w, binary.LittleEndian, uint32(0))          // TimeDateStamp
	binary.Write(w, binary.LittleEndian, uint32(symTabOff))  // PointerToSymbolTable
	binary.Write(w, binary.LittleEndian, uint32(numSyms))    // NumberOfSymbols
	binary.Write(w, binary.LittleEndian, uint16(0))          // SizeOfOptionalHeader
	binary.Write(w, binary.LittleEndian, uint16(0))          // Characteristics

	// ---- Section header (.rsrc) ----
	out.Write([]byte{'.', 'r', 's', 'r', 'c', 0, 0, 0}) // Name[8]
	binary.Write(w, binary.LittleEndian, uint32(0))                   // VirtualSize
	binary.Write(w, binary.LittleEndian, uint32(0))                   // VirtualAddress
	binary.Write(w, binary.LittleEndian, uint32(sectionSize))         // SizeOfRawData
	binary.Write(w, binary.LittleEndian, uint32(secDataOff))          // PointerToRawData
	binary.Write(w, binary.LittleEndian, uint32(relocOff))            // PointerToRelocations
	binary.Write(w, binary.LittleEndian, uint32(0))                   // PointerToLinenumbers
	binary.Write(w, binary.LittleEndian, uint16(numRelocs))           // NumberOfRelocations
	binary.Write(w, binary.LittleEndian, uint16(0))                   // NumberOfLinenumbers
	binary.Write(w, binary.LittleEndian, rsrcCharacteristics)         // Characteristics

	// ---- Section data ----
	out.Write(sec)

	// ---- Relocations ----
	// Reloc for DataEntry-A (version info)
	binary.Write(w, binary.LittleEndian, uint32(offDEA))        // VirtualAddress (site in section)
	binary.Write(w, binary.LittleEndian, uint32(0))             // SymbolTableIndex = .rsrc symbol
	binary.Write(w, binary.LittleEndian, imageRelAMD64Addr32NB) // Type

	// Reloc for DataEntry-B (manifest)
	binary.Write(w, binary.LittleEndian, uint32(offDEB))        // VirtualAddress (site in section)
	binary.Write(w, binary.LittleEndian, uint32(0))             // SymbolTableIndex = .rsrc symbol
	binary.Write(w, binary.LittleEndian, imageRelAMD64Addr32NB) // Type

	// ---- Symbol table ----
	out.Write([]byte{'.', 'r', 's', 'r', 'c', 0, 0, 0}) // ShortName[8]
	binary.Write(w, binary.LittleEndian, uint32(0))      // Value
	binary.Write(w, binary.LittleEndian, uint16(1))      // SectionNumber (1-based)
	binary.Write(w, binary.LittleEndian, uint16(0))      // Type
	out.WriteByte(imageSymClassStatic)                   // StorageClass
	out.WriteByte(1)                                     // NumberOfAuxSymbols

	// Auxiliary record for section symbol
	binary.Write(w, binary.LittleEndian, uint32(sectionSize)) // Length
	binary.Write(w, binary.LittleEndian, uint16(numRelocs))   // NumberOfRelocations
	binary.Write(w, binary.LittleEndian, uint16(0))           // NumberOfLinenumbers
	binary.Write(w, binary.LittleEndian, uint32(0))           // CheckSum
	binary.Write(w, binary.LittleEndian, uint16(1))           // Number (section index)
	out.WriteByte(0)                                          // Selection
	out.Write([]byte{0, 0, 0})                               // Padding → 18 bytes total

	// ---- String table (empty) ----
	binary.Write(w, binary.LittleEndian, uint32(strTabSize))

	return out.Bytes()
}
