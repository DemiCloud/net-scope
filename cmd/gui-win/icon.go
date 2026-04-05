//go:build windows

package guiwin

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
	"math"
	"runtime"
	"unsafe"
)

// createAppIcon generates a net-sweep icon at the given pixel size and returns
// an HICON. The icon is a dark-navy circle with white radar arcs, produced
// entirely from Go's image package — no .ico file or resource compiler needed.
func createAppIcon(size int) HICON {
	img := drawIcon(size)

	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return loadSystemIcon(IDI_APPLICATION)
	}
	data := buf.Bytes()

	r, _, _ := procCreateIconFromResourceEx.Call(
		uintptr(unsafe.Pointer(&data[0])),
		uintptr(len(data)),
		1,          // fIcon = TRUE
		0x00030000, // dwVersion 3.0
		uintptr(size), uintptr(size),
		LR_DEFAULTCOLOR,
	)
	runtime.KeepAlive(data)

	if r == 0 {
		return loadSystemIcon(IDI_APPLICATION)
	}
	return HICON(r)
}

// drawIcon renders the icon image: a dark-navy filled circle with three white
// concentric arcs (radar/sweep style) in the upper-right quadrant and a
// small white centre dot.
func drawIcon(size int) *image.RGBA {
	img := image.NewRGBA(image.Rect(0, 0, size, size))

	cx := float64(size) / 2.0
	radius := cx - 0.5

	bg := color.RGBA{18, 52, 120, 255}   // dark navy
	fg := color.RGBA{210, 230, 255, 255} // bright near-white

	arcRadii := [3]float64{0.36, 0.61, 0.86} // fractions of radius
	arcMin := -15.0 * math.Pi / 180.0         // -15° in radians
	arcMax := 75.0 * math.Pi / 180.0          //  75°

	arcThick := radius * 0.09 // arc line half-width
	dotR := radius * 0.13     // centre dot radius

	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			// Use pixel centre
			dx := float64(x) + 0.5 - cx
			dy := -(float64(y) + 0.5 - cx) // flip Y: positive = up
			dist := math.Sqrt(dx*dx + dy*dy)

			if dist > radius {
				continue // outside circle → transparent
			}

			img.SetRGBA(x, y, bg)

			// Radar arcs
			angle := math.Atan2(dy, dx)
			if angle >= arcMin && angle <= arcMax {
				for _, fr := range arcRadii {
					if math.Abs(dist-fr*radius) <= arcThick {
						img.SetRGBA(x, y, fg)
						break
					}
				}
			}

			// Centre dot
			if dist <= dotR {
				img.SetRGBA(x, y, fg)
			}
		}
	}
	return img
}
