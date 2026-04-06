// gen-rsrc generates cmd/gui-win/resource_windows_amd64.syso containing
// VERSIONINFO, application manifest, and icon resources for Explorer.
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
	"sort"
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
	IconPath string `json:"IconPath"`
}

type versionNum struct {
	Major, Minor, Patch, Build uint16
}

// resEntry holds one resource (type, name, language, data).
type resEntry struct {
	typeID uint32
	nameID uint32
	langID uint32
	data   []byte
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

	var entries []resEntry

	// RT_ICON (3) and RT_GROUP_ICON (14) — one RT_ICON per image in the .ico file.
	numIcons := 0
	if info.IconPath != "" {
		icoData, err := os.ReadFile(filepath.Join(*dir, info.IconPath))
		if err != nil {
			fmt.Fprintln(os.Stderr, "gen-rsrc: read icon:", err)
			os.Exit(1)
		}
		images, grp, err := parseICO(icoData)
		if err != nil {
			fmt.Fprintln(os.Stderr, "gen-rsrc: parse icon:", err)
			os.Exit(1)
		}
		for i, img := range images {
			entries = append(entries, resEntry{3, uint32(i + 1), 0x0409, img})
		}
		entries = append(entries, resEntry{14, 1, 0x0409, grp})
		numIcons = len(images)
	}

	// RT_VERSION (16)
	viData := buildVSVersionInfo(info)
	entries = append(entries, resEntry{16, 1, 0x0409, viData})

	// RT_MANIFEST (24)
	entries = append(entries, resEntry{24, 1, 0x0409, []byte(appManifest)})

	syso := buildCOFF(entries)
	outPath := filepath.Join(*dir, "resource_windows_amd64.syso")
	if err := os.WriteFile(outPath, syso, 0644); err != nil {
		fmt.Fprintln(os.Stderr, "gen-rsrc:", err)
		os.Exit(1)
	}
	iconMsg := ""
	if numIcons > 0 {
		iconMsg = fmt.Sprintf(", icons=%d", numIcons)
	}
	fmt.Printf("gen-rsrc: wrote %s (%d bytes, vi=%d bytes, manifest=%d bytes%s)\n",
		outPath, len(syso), len(viData), len(appManifest), iconMsg)
}

// ---------------------------------------------------------------------------
// ICO file parser
// ---------------------------------------------------------------------------

// parseICO extracts raw image blobs from a .ico file and builds the
// RT_GROUP_ICON blob that references them by sequential resource ID.
func parseICO(data []byte) (images [][]byte, grpIconDir []byte, err error) {
	if len(data) < 6 {
		return nil, nil, fmt.Errorf("ico: file too short")
	}
	le := binary.LittleEndian
	if le.Uint16(data[0:]) != 0 || le.Uint16(data[2:]) != 1 {
		return nil, nil, fmt.Errorf("ico: invalid header")
	}
	count := int(le.Uint16(data[4:]))
	if len(data) < 6+count*16 {
		return nil, nil, fmt.Errorf("ico: truncated directory")
	}

	// GRPICONDIR header (6 bytes) + GRPICONDIRENTRY per image (14 bytes each).
	grp := make([]byte, 6+count*14)
	le.PutUint16(grp[0:], 0)             // reserved
	le.PutUint16(grp[2:], 1)             // type = icon
	le.PutUint16(grp[4:], uint16(count)) // count

	images = make([][]byte, count)
	for i := 0; i < count; i++ {
		e := data[6+i*16:]
		bWidth      := e[0]
		bHeight     := e[1]
		bColorCount := e[2]
		bReserved   := e[3]
		wPlanes     := le.Uint16(e[4:])
		wBitCount   := le.Uint16(e[6:])
		byteCount   := le.Uint32(e[8:])
		imgOffset   := le.Uint32(e[12:])

		end := int(imgOffset) + int(byteCount)
		if end > len(data) {
			return nil, nil, fmt.Errorf("ico: image %d out of bounds", i)
		}
		images[i] = data[imgOffset:end]

		// GRPICONDIRENTRY (14 bytes)
		g := grp[6+i*14:]
		g[0] = bWidth
		g[1] = bHeight
		g[2] = bColorCount
		g[3] = bReserved
		le.PutUint16(g[4:], wPlanes)
		le.PutUint16(g[6:], wBitCount)
		le.PutUint32(g[8:], byteCount)
		le.PutUint16(g[12:], uint16(i+1)) // resource ID = sequential 1-based
	}
	return images, grp, nil
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
  <assemblyIdentity type="win32" name="demicloud.net-scope" version="1.0.0.0"
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
// COFF .syso builder (generic: supports any number of resource entries)
// ---------------------------------------------------------------------------

const (
	imageMachineAMD64       = uint16(0x8664)
	imageSCNInitializedData = uint32(0x00000040)
	imageSCNAlign4Bytes     = uint32(0x00300000)
	imageSCNMemRead         = uint32(0x40000000)
	imageRelAMD64Addr32NB   = uint16(0x0003)
	imageSymClassStatic     = byte(3)

	rsrcCharacteristics = imageSCNInitializedData | imageSCNAlign4Bytes | imageSCNMemRead
)

// buildCOFF packs resource entries into a minimal COFF .syso file.
//
// The .rsrc section contains a three-level resource directory tree:
//   Level 1  — resource type  (e.g. RT_ICON=3, RT_VERSION=16)
//   Level 2  — resource name/ID (e.g. 1 for first icon, 1 for version)
//   Level 3  — language  (always 0x0409 English here)
//   DataEntry — points to the raw resource blob via an ADDR32NB relocation
//
// Entries are sorted by (typeID, nameID, langID) before building.
// One RT_ICON entry per icon image size plus one RT_GROUP_ICON is the norm;
// add RT_VERSION and RT_MANIFEST to complete the set.
func buildCOFF(entries []resEntry) []byte {
	le := binary.LittleEndian

	// Sort entries by (typeID, nameID, langID).
	sort.Slice(entries, func(i, j int) bool {
		a, b := entries[i], entries[j]
		if a.typeID != b.typeID {
			return a.typeID < b.typeID
		}
		if a.nameID != b.nameID {
			return a.nameID < b.nameID
		}
		return a.langID < b.langID
	})

	// Group into typeRec → nameRec (one language per name in our usage).
	type nameRec struct {
		nameID  uint32
		langID  uint32
		dataIdx int
	}
	type typeRec struct {
		typeID uint32
		names  []nameRec
	}
	var types []typeRec
	for idx, e := range entries {
		var tr *typeRec
		for i := range types {
			if types[i].typeID == e.typeID {
				tr = &types[i]
				break
			}
		}
		if tr == nil {
			types = append(types, typeRec{typeID: e.typeID})
			tr = &types[len(types)-1]
		}
		tr.names = append(tr.names, nameRec{e.nameID, e.langID, idx})
	}

	numTypes := len(types)
	numData := len(entries)

	// ── Compute section offsets ───────────────────────────────────────────
	// Layout:  L1 dir | L2 dirs (one per type) | L3 dirs (one per name) |
	//          DataEntries (one per entry) | raw data blobs

	off := 16 + numTypes*8 // L1 directory

	l2Offs := make([]int, numTypes)
	for i, tr := range types {
		l2Offs[i] = off
		off += 16 + len(tr.names)*8
	}

	// l3Offs indexed by flat (type→name) order
	l3Offs := make([]int, numData)
	flat := 0
	for _, tr := range types {
		for range tr.names {
			l3Offs[flat] = off
			off += 24 // 16-byte header + 1 entry × 8 bytes
			flat++
		}
	}

	deOffs := make([]int, numData) // DataEntry offsets
	for i := range entries {
		deOffs[i] = off
		off += 16
	}
	dirEnd := off

	dataOffs := make([]int, numData) // raw blob offsets
	dataEnd := dirEnd
	for i, e := range entries {
		dataOffs[i] = dataEnd
		dataEnd += align4(len(e.data))
	}
	sectionSize := dataEnd

	// ── Fill section buffer ───────────────────────────────────────────────
	sec := make([]byte, sectionSize)

	putDir := func(off, n int) {
		le.PutUint16(sec[off+12:], 0)
		le.PutUint16(sec[off+14:], uint16(n))
	}
	putDirEntry := func(dirOff, idx int, id uint32, target int, isSubdir bool) {
		p := dirOff + 16 + idx*8
		le.PutUint32(sec[p:], id)
		if isSubdir {
			le.PutUint32(sec[p+4:], 0x80000000|uint32(target))
		} else {
			le.PutUint32(sec[p+4:], uint32(target))
		}
	}

	// Level 1
	putDir(0, numTypes)
	for i, tr := range types {
		putDirEntry(0, i, tr.typeID, l2Offs[i], true)
	}

	// Level 2 + Level 3
	flat = 0
	for i, tr := range types {
		putDir(l2Offs[i], len(tr.names))
		for j, nr := range tr.names {
			putDirEntry(l2Offs[i], j, nr.nameID, l3Offs[flat], true)
			// Level 3 (always 1 language)
			putDir(l3Offs[flat], 1)
			putDirEntry(l3Offs[flat], 0, nr.langID, deOffs[nr.dataIdx], false)
			flat++
		}
	}

	// DataEntries + raw blobs
	for i, e := range entries {
		p := deOffs[i]
		le.PutUint32(sec[p:], uint32(dataOffs[i]))   // OffsetToData (patched by ADDR32NB reloc)
		le.PutUint32(sec[p+4:], uint32(len(e.data))) // Size
		// CodePage and Reserved stay 0
		copy(sec[dataOffs[i]:], e.data)
	}

	// ── COFF file wrapper ─────────────────────────────────────────────────
	const (
		coffHdrSize = 20
		sectHdrSize = 40
		relocSize   = 10
		numSyms     = 2
		strTabSize  = 4
	)
	secDataFileOff := coffHdrSize + sectHdrSize
	relocFileOff   := secDataFileOff + sectionSize
	symTabFileOff  := relocFileOff + numData*relocSize

	var out bytes.Buffer
	w := &out

	// COFF header
	binary.Write(w, binary.LittleEndian, imageMachineAMD64)
	binary.Write(w, binary.LittleEndian, uint16(1))               // NumberOfSections
	binary.Write(w, binary.LittleEndian, uint32(0))               // TimeDateStamp
	binary.Write(w, binary.LittleEndian, uint32(symTabFileOff))   // PointerToSymbolTable
	binary.Write(w, binary.LittleEndian, uint32(numSyms))         // NumberOfSymbols
	binary.Write(w, binary.LittleEndian, uint16(0))               // SizeOfOptionalHeader
	binary.Write(w, binary.LittleEndian, uint16(0))               // Characteristics

	// Section header (.rsrc)
	out.Write([]byte{'.', 'r', 's', 'r', 'c', 0, 0, 0})
	binary.Write(w, binary.LittleEndian, uint32(0))               // VirtualSize
	binary.Write(w, binary.LittleEndian, uint32(0))               // VirtualAddress
	binary.Write(w, binary.LittleEndian, uint32(sectionSize))     // SizeOfRawData
	binary.Write(w, binary.LittleEndian, uint32(secDataFileOff))  // PointerToRawData
	binary.Write(w, binary.LittleEndian, uint32(relocFileOff))    // PointerToRelocations
	binary.Write(w, binary.LittleEndian, uint32(0))               // PointerToLinenumbers
	binary.Write(w, binary.LittleEndian, uint16(numData))         // NumberOfRelocations
	binary.Write(w, binary.LittleEndian, uint16(0))               // NumberOfLinenumbers
	binary.Write(w, binary.LittleEndian, rsrcCharacteristics)

	// Section data
	out.Write(sec)

	// Relocations: one IMAGE_RELOCATION per DataEntry
	for i := range entries {
		binary.Write(w, binary.LittleEndian, uint32(deOffs[i]))    // VirtualAddress (site in section)
		binary.Write(w, binary.LittleEndian, uint32(0))            // SymbolTableIndex (.rsrc symbol)
		binary.Write(w, binary.LittleEndian, imageRelAMD64Addr32NB)
	}

	// Symbol table: section symbol + auxiliary record (18 bytes each)
	out.Write([]byte{'.', 'r', 's', 'r', 'c', 0, 0, 0}) // ShortName[8]
	binary.Write(w, binary.LittleEndian, uint32(0))      // Value
	binary.Write(w, binary.LittleEndian, uint16(1))      // SectionNumber (1-based)
	binary.Write(w, binary.LittleEndian, uint16(0))      // Type
	out.WriteByte(imageSymClassStatic)
	out.WriteByte(1) // NumberOfAuxSymbols

	// Auxiliary record for section symbol (18 bytes)
	binary.Write(w, binary.LittleEndian, uint32(sectionSize)) // Length
	binary.Write(w, binary.LittleEndian, uint16(numData))     // NumberOfRelocations
	binary.Write(w, binary.LittleEndian, uint16(0))           // NumberOfLinenumbers
	binary.Write(w, binary.LittleEndian, uint32(0))           // CheckSum
	binary.Write(w, binary.LittleEndian, uint16(1))           // Number (section index)
	out.WriteByte(0)                                          // Selection
	out.Write([]byte{0, 0, 0})                               // Padding → 18 bytes total

	// String table (empty — just the size field)
	binary.Write(w, binary.LittleEndian, uint32(strTabSize))

	return out.Bytes()
}
