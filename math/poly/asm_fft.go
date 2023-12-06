//go:build !(amd64 && !purego)

package poly

import (
	"math"
)

// fftInPlace is a top-level function for FFT.
// All internal FFT implementations calls this function for performance.
func fftInPlace(coeffs, wNj []complex128) {
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

// InvfftInPlace is a top-level function for inverse FFT.
// All internal inverse FFT implementations calls this function for performance.
func invFFTInPlace(coeffs, wNjInv []complex128) {
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

// twistInPlace twists the coefficients before FFT.
// Equivalent to coeffs * w2Nj.
func twistInPlace(coeffs, w2Nj []complex128) {
	elementWiseMulCmplxAssign(coeffs, w2Nj, coeffs)
}

// twistAndScaleInPlace twists the coefficients before FFT and scales it with maxTInv.
func twistAndScaleInPlace(coeffs, w2Nj []complex128, maxTInv float64) {
	for i := 0; i < len(coeffs); i++ {
		coeffs[i] = coeffs[i] * w2Nj[i] * complex(maxTInv, 0)
	}
}

// unTwistInPlace untwists the coefficients after inverse FFT.
// Equivalent to coeffs * w2NjInv.
func unTwistInPlace(coeffs, w2NjInv []complex128) {
	for i := 0; i < len(coeffs); i++ {
		c := coeffs[i] * w2NjInv[i]

		coeffs[i] = complex(math.Round(real(c)), math.Round(imag(c)))
	}
}

// unTwistAndScaleInPlace untwists the coefficients and scales it with maxT.
func unTwistAndScaleInPlace(coeffs, w2NjInv []complex128, maxT float64) {
	for i := 0; i < len(coeffs); i++ {
		c := coeffs[i] * w2NjInv[i]
		cr := real(c)
		ci := imag(c)

		coeffs[i] = complex((cr-math.Round(cr))*maxT, (ci-math.Round(ci))*maxT)
	}
}
