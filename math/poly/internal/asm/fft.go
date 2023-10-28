//go:build !amd64

package asm

// FFTInPlace is a top-level function for FFTInPlace.
// All internal FFT implementations calls this function for performance.
func FFTInPlace(coeffs, wNj []complex128) {
	// Implementation of Algorithm 1 from https://eprint.iacr.org/2016/504.pdf
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
func InvFFTInPlace(coeffs, wNjInv []complex128) {
	// Implementation of Algorithm 2 from https://eprint.iacr.org/2016/504.pdf
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
