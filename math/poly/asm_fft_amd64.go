//go:build amd64 && !purego

package poly

import (
	"math"

	"golang.org/x/sys/cpu"
)

func fftInPlaceAVX2(coeffs, wNj []complex128)

// fftInPlace is a top-level function for FFT.
// All internal FFT implementations calls this function for performance.
func fftInPlace(coeffs, wNj []complex128) {
	if cpu.X86.HasAVX2 && cpu.X86.HasFMA {
		fftInPlaceAVX2(coeffs, wNj)
		return
	}

	// Implementation of Algorithm 1 from https://eprint.iacr.org/2016/504
	N := len(coeffs)
	t := N
	for m := 1; m < N; m <<= 1 {
		t >>= 1
		for i := 0; i < m; i++ {
			j1 := i * t << 1
			j2 := j1 + t
			for j := j1; j < j2; j++ {
				U, V := coeffs[j], coeffs[j+t]*wNj[m+i]
				coeffs[j], coeffs[j+t] = U+V, U-V
			}
		}
	}
}

func invFFTInPlaceAVX2(coeffs, wNjInv []complex128)

// InvfftInPlace is a top-level function for inverse FFT.
// All internal inverse FFT implementations calls this function for performance.
func invFFTInPlace(coeffs, wNjInv []complex128) {
	if cpu.X86.HasAVX2 && cpu.X86.HasFMA {
		invFFTInPlaceAVX2(coeffs, wNjInv)
		return
	}

	// Implementation of Algorithm 2 from https://eprint.iacr.org/2016/504
	N := len(coeffs)
	t := 1
	for m := N; m > 1; m >>= 1 {
		j1 := 0
		h := m >> 1
		for i := 0; i < h; i++ {
			j2 := j1 + t
			for j := j1; j < j2; j++ {
				U, V := coeffs[j], coeffs[j+t]
				coeffs[j], coeffs[j+t] = U+V, (U-V)*wNjInv[h+i]
			}
			j1 += t << 1
		}
		t <<= 1
	}
}

func untwistInPlaceAVX2(coeffs, w2NjInv []complex128)

// unTwistInPlace untwists the coefficients after inverse FFT.
// Equivalent to coeffs * w2NjInv.
func unTwistInPlace(coeffs, w2NjInv []complex128) {
	if cpu.X86.HasAVX2 && cpu.X86.HasFMA {
		untwistInPlaceAVX2(coeffs, w2NjInv)
		return
	}

	for i := 0; i < len(coeffs); i++ {
		c := coeffs[i] * w2NjInv[i]

		coeffs[i] = complex(math.Round(real(c)), math.Round(imag(c)))
	}
}

func untwistAndScaleInPlaceAVX2(coeffs, w2NjInv []complex128, maxT float64)

// unTwistAndScaleInPlace untwists the coefficients and scales it with maxT.
func unTwistAndScaleInPlace(coeffs, w2NjInv []complex128, maxT float64) {
	if cpu.X86.HasAVX2 && cpu.X86.HasFMA {
		untwistAndScaleInPlaceAVX2(coeffs, w2NjInv, maxT)
		return
	}

	for i := 0; i < len(coeffs); i++ {
		c := coeffs[i] * w2NjInv[i]
		cr := real(c)
		ci := imag(c)

		coeffs[i] = complex((cr-math.Round(cr))*maxT, (ci-math.Round(ci))*maxT)
	}
}
