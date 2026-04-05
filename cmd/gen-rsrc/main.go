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
	syso := buildCOFF(viData)

	outPath := filepath.Join(*dir, "resource_windows_amd64.syso")
	if err := os.WriteFile(outPath, syso, 0644); err != nil {
		fmt.Fprintln(os.Stderr, "gen-rsrc:", err)
		os.Exit(1)
	}
	fmt.Printf("gen-rsrc: wrote %s (%d bytes, vi=%d bytes)\n", outPath, len(syso), len(viData))
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

// buildCOFF wraps viData inside a minimal COFF object file (.syso) that the
// Go linker will include automatically. The single .rsrc section holds:
//
//   level-1 ResDir (type = RT_VERSION=16)
//   level-2 ResDir (id = 1)
//   level-3 ResDir (language = 0x0409)
//   ResDataEntry   (with ADDR32NB relocation filling in the RVA)
//   viData bytes
func buildCOFF(viData []byte) []byte {
	// Pad viData to DWORD boundary.
	padded := make([]byte, align4(len(viData)))
	copy(padded, viData)

	// Resource section layout (all offsets from section start):
	//   0  : level-1 ResDir       (16 bytes)
	//   16 : level-1 Entry × 1    (8 bytes)   → 24
	//  24  : level-2 ResDir       (16 bytes)
	//  40  : level-2 Entry × 1    (8 bytes)   → 48
	//  48  : level-3 ResDir       (16 bytes)
	//  64  : level-3 Entry × 1    (8 bytes)   → 72
	//  72  : ResDataEntry         (16 bytes)  → 88
	//  88  : viData (padded)
	const (
		offL1    = 0
		offL2    = 24
		offL3    = 48
		offDE    = 72
		offData  = 88
	)
	sectionSize := offData + len(padded)
	sec := make([]byte, sectionSize)

	putDir := func(off int, numID uint16) {
		// IMAGE_RESOURCE_DIRECTORY: 16 bytes (fields at bytes 12-13=named, 14-15=id)
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

	putDir(offL1, 1)
	putEntry(offL1+16, 16, offL2, true) // RT_VERSION = 16

	putDir(offL2, 1)
	putEntry(offL2+16, 1, offL3, true) // resource id = 1

	putDir(offL3, 1)
	putEntry(offL3+16, 0x0409, offDE, false) // language = English US

	// IMAGE_RESOURCE_DATA_ENTRY
	le := binary.LittleEndian
	le.PutUint32(sec[offDE:], uint32(offData))       // OffsetToData (relocation addend)
	le.PutUint32(sec[offDE+4:], uint32(len(viData))) // Size (original, not padded)
	// CodePage=0, Reserved=0 (already zero from make)

	copy(sec[offData:], padded)

	// COFF file layout:
	//   [0]                  : COFF header (20 bytes)
	//   [20]                 : Section header (40 bytes)
	//   [60]                 : Section data (sectionSize bytes)
	//   [60+sectionSize]     : Relocation (10 bytes × 1)
	//   [60+sectionSize+10]  : Symbol table (18 bytes × 2)
	//   [60+sectionSize+46]  : String table (4 bytes = empty)
	const (
		coffHdrSize  = 20
		sectHdrSize  = 40
		relocSize    = 10
		symEntrySize = 18
		numSyms      = 2  // section symbol + aux record
		strTabSize   = 4
	)
	secDataOff := coffHdrSize + sectHdrSize
	relocOff   := secDataOff + sectionSize
	symTabOff  := relocOff + relocSize

	var out bytes.Buffer
	w := &out

	// ---- COFF header ----
	binary.Write(w, binary.LittleEndian, imageMachineAMD64) // Machine
	binary.Write(w, binary.LittleEndian, uint16(1))         // NumberOfSections
	binary.Write(w, binary.LittleEndian, uint32(0))         // TimeDateStamp
	binary.Write(w, binary.LittleEndian, uint32(symTabOff)) // PointerToSymbolTable
	binary.Write(w, binary.LittleEndian, uint32(numSyms))   // NumberOfSymbols
	binary.Write(w, binary.LittleEndian, uint16(0))         // SizeOfOptionalHeader
	binary.Write(w, binary.LittleEndian, uint16(0))         // Characteristics

	// ---- Section header (.rsrc) ----
	out.Write([]byte{'.', 'r', 's', 'r', 'c', 0, 0, 0}) // Name[8]
	binary.Write(w, binary.LittleEndian, uint32(0))                    // VirtualSize
	binary.Write(w, binary.LittleEndian, uint32(0))                    // VirtualAddress
	binary.Write(w, binary.LittleEndian, uint32(sectionSize))          // SizeOfRawData
	binary.Write(w, binary.LittleEndian, uint32(secDataOff))           // PointerToRawData
	binary.Write(w, binary.LittleEndian, uint32(relocOff))             // PointerToRelocations
	binary.Write(w, binary.LittleEndian, uint32(0))                    // PointerToLinenumbers
	binary.Write(w, binary.LittleEndian, uint16(1))                    // NumberOfRelocations
	binary.Write(w, binary.LittleEndian, uint16(0))                    // NumberOfLinenumbers
	binary.Write(w, binary.LittleEndian, rsrcCharacteristics)          // Characteristics

	// ---- Section data ----
	out.Write(sec)

	// ---- Relocation: fix up ResDataEntry.OffsetToData → section-relative RVA ----
	binary.Write(w, binary.LittleEndian, uint32(offDE))           // VirtualAddress (site within section)
	binary.Write(w, binary.LittleEndian, uint32(0))               // SymbolTableIndex (= .rsrc symbol)
	binary.Write(w, binary.LittleEndian, imageRelAMD64Addr32NB)   // Type

	// ---- Symbol table ----
	// Entry 0: .rsrc section symbol
	out.Write([]byte{'.', 'r', 's', 'r', 'c', 0, 0, 0}) // ShortName[8]
	binary.Write(w, binary.LittleEndian, uint32(0))      // Value
	binary.Write(w, binary.LittleEndian, uint16(1))      // SectionNumber (1-based)
	binary.Write(w, binary.LittleEndian, uint16(0))      // Type
	out.WriteByte(imageSymClassStatic)                   // StorageClass
	out.WriteByte(1)                                     // NumberOfAuxSymbols

	// Entry 1: Auxiliary record for section symbol
	binary.Write(w, binary.LittleEndian, uint32(sectionSize)) // Length
	binary.Write(w, binary.LittleEndian, uint16(1))           // NumberOfRelocations
	binary.Write(w, binary.LittleEndian, uint16(0))           // NumberOfLinenumbers
	binary.Write(w, binary.LittleEndian, uint32(0))           // CheckSum
	binary.Write(w, binary.LittleEndian, uint16(1))           // Number (section index)
	out.WriteByte(0)                                          // Selection
	out.Write([]byte{0, 0, 0})                               // Padding (3 bytes → total 18)

	// ---- String table (empty: just the 4-byte size field) ----
	binary.Write(w, binary.LittleEndian, uint32(strTabSize))

	return out.Bytes()
}
