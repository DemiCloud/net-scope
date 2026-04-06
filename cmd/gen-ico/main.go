// gen-ico generates cmd/gui-win/icon.ico from the same network-topology artwork
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

// drawIcon renders the NetScope icon: a deep-navy circle with three concentric
// teal network-topology rings graduating from bright (outer) to dim (inner),
// node dots at each ring, and radial spokes connecting adjacent layers.
// Kept in sync with cmd/gui-win/icon.go drawIcon().
func drawIcon(size int) *image.RGBA {
	img := image.NewRGBA(image.Rect(0, 0, size, size))
	cx := float64(size) / 2.0 // center x = center y (square icon)
	R := cx - 0.5             // bounding circle radius

	// Palette
	bg     := color.RGBA{10, 20, 40, 255}   // deep navy
	colS   := color.RGBA{30, 96, 130, 80}   // scope boundary ring (faint)
	col1   := color.RGBA{0, 212, 180, 255}  // outer ring — bright teal
	col2   := color.RGBA{0, 158, 138, 210}  // mid ring
	col3   := color.RGBA{0, 96, 104, 160}   // inner ring — dim
	colSpk := color.RGBA{0, 170, 155, 130}  // inter-ring spokes
	colHub := color.RGBA{0, 80, 80, 110}    // centre glow

	// Fractional ring radii (fraction of R)
	const (
		rS = 0.94 // scope ring
		r1 = 0.76 // outer ring
		r2 = 0.54 // mid ring
		r3 = 0.32 // inner ring
	)
	ht  := math.Max(0.5, R*0.018) // ring half-thickness
	hsp := math.Max(0.5, R*0.015) // spoke half-width
	nr1 := math.Max(1.0, R*0.065) // node radius — outer
	nr2 := math.Max(1.0, R*0.056) // node radius — mid
	nr3 := math.Max(1.0, R*0.047) // node radius — inner

	// Node angles (0=right, CCW positive, degrees)
	nodes1 := [6]float64{0, 60, 120, 180, 240, 300}
	nodes2 := [4]float64{30, 120, 210, 300}
	nodes3 := [3]float64{90, 210, 330}

	// Spoke angles: ring1↔ring2 at shared angles 120°, 300°; ring2↔ring3 at 210°
	spk12 := [2]float64{120, 300}
	spk23 := [1]float64{210}

	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			px, py := float64(x)+0.5, float64(y)+0.5
			dist := math.Sqrt(iconSq(px-cx) + iconSq(py-cx))
			if dist > R+0.5 {
				continue // outside → transparent
			}

			c := bg

			// Scope boundary ring
			c = iconOver(c, colS, iconRingCov(dist, R*rS, math.Max(0.3, R*0.009)))

			// Inner ring + nodes
			c = iconOver(c, col3, iconRingCov(dist, R*r3, ht))
			for _, deg := range nodes3 {
				a := deg * math.Pi / 180
				d := math.Sqrt(iconSq(px-(cx+R*r3*math.Cos(a))) + iconSq(py-(cx-R*r3*math.Sin(a))))
				c = iconOver(c, col3, iconFillCov(d, nr3))
			}

			// Mid ring + nodes
			c = iconOver(c, col2, iconRingCov(dist, R*r2, ht))
			for _, deg := range nodes2 {
				a := deg * math.Pi / 180
				d := math.Sqrt(iconSq(px-(cx+R*r2*math.Cos(a))) + iconSq(py-(cx-R*r2*math.Sin(a))))
				c = iconOver(c, col2, iconFillCov(d, nr2))
			}

			// Outer ring + nodes
			c = iconOver(c, col1, iconRingCov(dist, R*r1, ht))
			for _, deg := range nodes1 {
				a := deg * math.Pi / 180
				d := math.Sqrt(iconSq(px-(cx+R*r1*math.Cos(a))) + iconSq(py-(cx-R*r1*math.Sin(a))))
				c = iconOver(c, col1, iconFillCov(d, nr1))
			}

			// Radial spokes between adjacent rings
			for _, deg := range spk12 {
				a := deg * math.Pi / 180
				d := iconSegDist(px, py,
					cx+R*r1*math.Cos(a), cx-R*r1*math.Sin(a),
					cx+R*r2*math.Cos(a), cx-R*r2*math.Sin(a))
				c = iconOver(c, colSpk, iconFillCov(d, hsp))
			}
			for _, deg := range spk23 {
				a := deg * math.Pi / 180
				d := iconSegDist(px, py,
					cx+R*r2*math.Cos(a), cx-R*r2*math.Sin(a),
					cx+R*r3*math.Cos(a), cx-R*r3*math.Sin(a))
				c = iconOver(c, colSpk, iconFillCov(d, hsp))
			}

			// Centre glow — marks the innermost hub
			c = iconOver(c, colHub, iconFillCov(dist, math.Max(1.0, R*0.10)))

			// Clip to bounding circle with 1px anti-alias
			alpha := iconClamp01(R + 0.5 - dist)
			c.A = uint8(float64(c.A) * alpha)
			img.SetRGBA(x, y, c)
		}
	}
	return img
}

// iconRingCov returns 1px-anti-aliased coverage for a ring at radius r.
func iconRingCov(dist, r, halfThick float64) float64 {
	return iconClamp01(halfThick + 0.5 - math.Abs(dist-r))
}

// iconFillCov returns 1px-anti-aliased coverage for a filled disc of radius r.
func iconFillCov(dist, r float64) float64 {
	return iconClamp01(r + 0.5 - dist)
}

// iconSegDist returns the distance from (px,py) to the nearest point on the
// line segment (x1,y1)–(x2,y2).
func iconSegDist(px, py, x1, y1, x2, y2 float64) float64 {
	dx, dy := x2-x1, y2-y1
	lenSq := dx*dx + dy*dy
	if lenSq == 0 {
		return math.Sqrt(iconSq(px-x1) + iconSq(py-y1))
	}
	t := iconClamp01(((px-x1)*dx + (py-y1)*dy) / lenSq)
	return math.Sqrt(iconSq(px-x1-t*dx) + iconSq(py-y1-t*dy))
}

// iconOver composites src over dst (dst assumed fully opaque) at coverage t.
func iconOver(dst, src color.RGBA, t float64) color.RGBA {
	if t <= 0 {
		return dst
	}
	a := t * float64(src.A) / 255.0
	if a > 1 {
		a = 1
	}
	return color.RGBA{
		uint8(float64(dst.R)*(1-a) + float64(src.R)*a),
		uint8(float64(dst.G)*(1-a) + float64(src.G)*a),
		uint8(float64(dst.B)*(1-a) + float64(src.B)*a),
		255,
	}
}

func iconClamp01(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}

func iconSq(x float64) float64 { return x * x }
