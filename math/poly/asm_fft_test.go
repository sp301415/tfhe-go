package poly

import (
	"math/cmplx"
	"math/rand"
	"testing"
)

func fftInPlaceGeneric(coeffs, wNj []complex128) {
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

func invFFTInPlaceGeneric(coeffs, wNjInv []complex128) {
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

func TestFFTAssembly(t *testing.T) {
	N := 1 << 10
	eps := 1e-5

	coeffs := make([]complex128, N)
	coeffsAVX2 := make([]complex128, N)
	wNj := make([]complex128, N)
	for i := range coeffs {
		coeffs[i] = complex(rand.NormFloat64(), rand.NormFloat64())
		wNj[i] = complex(rand.NormFloat64(), rand.NormFloat64())
	}

	t.Run("FFT", func(t *testing.T) {
		copy(coeffsAVX2, coeffs)
		fftInPlaceGeneric(coeffs, wNj)

		fftInPlace(coeffsAVX2, wNj)

		for i := 0; i < N; i++ {
			if cmplx.Abs(coeffs[i]-coeffsAVX2[i]) > eps {
				t.Fatalf("FFT: %v != %v", coeffs[i], coeffsAVX2[i])
			}
		}
	})

	t.Run("InvFFT", func(t *testing.T) {
		copy(coeffsAVX2, coeffs)
		invFFTInPlaceGeneric(coeffs, wNj)
		invFFTInPlace(coeffsAVX2, wNj)

		for i := 0; i < N; i++ {
			if cmplx.Abs(coeffs[i]-coeffsAVX2[i]) > eps {
				t.Fatalf("InvFFT: %v != %v", coeffs[i], coeffsAVX2[i])
			}
		}
	})
}

func BenchmarkFFTAssembly(b *testing.B) {
	N := 1 << 15

	coeffs := make([]complex128, N)
	wNj := make([]complex128, N)
	for i := range coeffs {
		coeffs[i] = complex(rand.NormFloat64(), rand.NormFloat64())
		wNj[i] = complex(rand.NormFloat64(), rand.NormFloat64())
	}

	b.Run("FFT", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			fftInPlaceGeneric(coeffs, wNj)
		}
	})

	b.Run("FFTAVX2", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			fftInPlace(coeffs, wNj)
		}
	})

	b.Run("InvFFT", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			invFFTInPlaceGeneric(coeffs, wNj)
		}
	})

	b.Run("InvFFTAVX2", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			invFFTInPlace(coeffs, wNj)
		}
	})
}
