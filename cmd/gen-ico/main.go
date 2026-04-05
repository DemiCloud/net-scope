// gen-ico generates cmd/gui-win/icon.ico from the same radar-sweep artwork
// used as the window icon at runtime. Run via "go run ./cmd/gen-ico/".
package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"math"
	"os"
)

func main() {
	out := flag.String("o", "cmd/gui-win/icon.ico", "output .ico file path")
	flag.Parse()

	sizes := []int{16, 32, 48, 256}
	var pngData [][]byte
	for _, sz := range sizes {
		var buf bytes.Buffer
		if err := png.Encode(&buf, drawIcon(sz)); err != nil {
			fmt.Fprintf(os.Stderr, "gen-ico: encode %dpx: %v\n", sz, err)
			os.Exit(1)
		}
		pngData = append(pngData, buf.Bytes())
	}

	f, err := os.Create(*out)
	if err != nil {
		fmt.Fprintf(os.Stderr, "gen-ico: create %s: %v\n", *out, err)
		os.Exit(1)
	}
	defer f.Close()

	N := uint16(len(sizes))
	// ICONDIR header (6 bytes)
	_ = binary.Write(f, binary.LittleEndian, uint16(0)) // reserved
	_ = binary.Write(f, binary.LittleEndian, uint16(1)) // type=icon
	_ = binary.Write(f, binary.LittleEndian, N)

	// First image data begins after header (6) + N directory entries (16 each).
	offsets := make([]uint32, N)
	off := uint32(6 + 16*int(N))
	for i, d := range pngData {
		offsets[i] = off
		off += uint32(len(d))
	}

	// ICONDIRENTRY × N (16 bytes each)
	for i, sz := range sizes {
		w, h := byte(sz), byte(sz)
		if sz == 256 {
			w, h = 0, 0 // 0 means 256 in the ICO spec
		}
		f.Write([]byte{w, h, 0, 0}) // width, height, colorCount=0, reserved=0
		_ = binary.Write(f, binary.LittleEndian, uint16(1))               // planes
		_ = binary.Write(f, binary.LittleEndian, uint16(32))              // bit depth
		_ = binary.Write(f, binary.LittleEndian, uint32(len(pngData[i]))) // bytes
		_ = binary.Write(f, binary.LittleEndian, offsets[i])              // offset
	}

	// Image data
	for _, d := range pngData {
		f.Write(d)
	}
	fmt.Printf("gen-ico: wrote %d-image icon to %s\n", N, *out)
}

// drawIcon renders the radar-sweep icon at the given pixel size.
// Kept in sync with cmd/gui-win/icon.go drawIcon().
func drawIcon(size int) *image.RGBA {
	img := image.NewRGBA(image.Rect(0, 0, size, size))

	cx := float64(size) / 2.0
	radius := cx - 0.5

	bg := color.RGBA{18, 52, 120, 255}   // dark navy
	fg := color.RGBA{210, 230, 255, 255} // bright near-white

	arcRadii := [3]float64{0.36, 0.61, 0.86}
	arcMin := -15.0 * math.Pi / 180.0
	arcMax := 75.0 * math.Pi / 180.0
	arcThick := radius * 0.09
	dotR := radius * 0.13

	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			dx := float64(x) + 0.5 - cx
			dy := -(float64(y) + 0.5 - cx)
			dist := math.Sqrt(dx*dx + dy*dy)

			if dist > radius {
				continue // transparent outside circle
			}
			img.SetRGBA(x, y, bg)

			angle := math.Atan2(dy, dx)
			if angle >= arcMin && angle <= arcMax {
				for _, fr := range arcRadii {
					if math.Abs(dist-fr*radius) <= arcThick {
						img.SetRGBA(x, y, fg)
						break
					}
				}
			}
			if dist <= dotR {
				img.SetRGBA(x, y, fg)
			}
		}
	}
	return img
}
