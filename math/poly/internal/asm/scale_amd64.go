//go:build amd64

package asm

import (
	"math"

	"golang.org/x/sys/cpu"
)

func mulAndScaleAVX2(x, y complex128, maxT float64) (float64, float64)

// MulAndScale multiplies x, y and scales it according to maxT.
// Roughly equivalent to:
//
//	func(x, y complex128, maxT float64) (float64, float64) {
//		z := x * y
//		z0 := real(z)
//		z1 := imag(z)
//		return (z0 - round(z0)) * maxT, (z1 - round(z1)) * maxT
func MulAndScale(x, y complex128, maxT float64) (float64, float64) {
	if cpu.X86.HasFMA && cpu.X86.HasAVX2 {
		return mulAndScaleAVX2(x, y, maxT)
	}

	z := x * y
	z0 := real(z)
	z1 := imag(z)

	return (z0 - math.Round(z0)) * maxT, (z1 - math.Round(z1)) * maxT
}
