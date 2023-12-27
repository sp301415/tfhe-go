//go:build !(amd64 && !purego)

package poly

import (
	"math"
)

// fftInPlace is a top-level function for FFT.
// All internal FFT implementations calls this function for performance.
func fftInPlace(coeffs, wNj []complex128) {
	N := len(coeffs)

	for j := 0; j < N/2; j++ {
		U, V := coeffs[j], coeffs[j+N/2]
		coeffs[j], coeffs[j+N/2] = U+V, U-V
	}

	t := N / 2
	for m := 2; m < N; m <<= 1 {
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

// InvfftInPlace is a top-level function for inverse FFT.
// All internal inverse FFT implementations calls this function for performance.
func invFFTInPlace(coeffs, wNjInv []complex128) {
	N := len(coeffs)

	t := 1
	k := 0
	for m := N; m > 2; m >>= 1 {
		j1 := 0
		h := m >> 1
		for i := 0; i < h; i++ {
			j2 := j1 + t
			for j := j1; j < j2; j++ {
				U, V := coeffs[j], coeffs[j+t]
				coeffs[j], coeffs[j+t] = U+V, (U-V)*wNjInv[k+i]
			}
			j1 += t << 1
		}
		t <<= 1
		k += h
	}

	for j := 0; j < N/2; j++ {
		U, V := coeffs[j], coeffs[j+N/2]
		coeffs[j], coeffs[j+N/2] = U+V, U-V
	}
}

// untwistInPlace untwists the coefficients after inverse FFT.
// Equivalent to coeffs * w2NjInv.
func untwistInPlace(coeffs, w2NjInv []complex128) {
	for i := 0; i < len(coeffs); i++ {
		c := coeffs[i] * w2NjInv[i]
		coeffs[i] = complex(math.Round(real(c)), math.Round(imag(c)))
	}
}

// untwistAndScaleInPlace untwists the coefficients and scales it with maxT.
func untwistAndScaleInPlace(coeffs, w2NjInv []complex128, maxT float64) {
	for i := 0; i < len(coeffs); i++ {
		c := coeffs[i] * w2NjInv[i]
		cr := real(c)
		ci := imag(c)

		coeffs[i] = complex((cr-math.Round(cr))*maxT, (ci-math.Round(ci))*maxT)
	}
}
