package poly

import (
	"math"
	"math/cmplx"
	"math/rand"
	"testing"

	"github.com/sp301415/tfhe-go/math/vec"
)

func fftInPlaceRef(coeffs, wNj []complex128) {
	N := len(coeffs)

	t := N
	for m := 1; m < N; m <<= 1 {
		t >>= 1
		for i := 0; i < m; i++ {
			j1 := i * t << 1
			j2 := j1 + t
			for j := j1; j < j2; j++ {
				U, V := coeffs[j], coeffs[j+t]*wNj[i]
				coeffs[j], coeffs[j+t] = U+V, U-V
			}
		}
	}
}

func invFFTInPlaceRef(coeffs, wNjInv []complex128) {
	N := len(coeffs)

	t := 1
	for m := N; m > 1; m >>= 1 {
		j1 := 0
		h := m >> 1
		for i := 0; i < h; i++ {
			j2 := j1 + t
			for j := j1; j < j2; j++ {
				U, V := coeffs[j], coeffs[j+t]
				coeffs[j], coeffs[j+t] = U+V, (U-V)*wNjInv[i]
			}
			j1 += t << 1
		}
		t <<= 1
	}
}

func TestFFTAssembly(t *testing.T) {
	N := 16
	eps := 1e-10

	coeffs := make([]complex128, N)
	for i := 0; i < N; i++ {
		coeffs[i] = complex(rand.Float64(), rand.Float64())
	}
	coeffsAVX2 := vec.CmplxToFloat4(coeffs)
	coeffsAVX2Out := make([]complex128, N)

	wNjRef := make([]complex128, N/2)
	wNjInvRef := make([]complex128, N/2)
	for j := 0; j < N/2; j++ {
		e := -2 * math.Pi * float64(j) / float64(N)
		wNjRef[j] = cmplx.Exp(complex(0, e))
		wNjInvRef[j] = cmplx.Exp(-complex(0, e))
	}
	vec.BitReverseInPlace(wNjRef)
	vec.BitReverseInPlace(wNjInvRef)

	wNj, wNjInv := genTwiddleFactors(N)

	t.Run("FFT", func(t *testing.T) {
		vec.CmplxToFloat4Assign(coeffs, coeffsAVX2)
		fftInPlaceRef(coeffs, wNjRef)

		fftInPlace(coeffsAVX2, wNj)
		vec.Float4ToCmplxAssign(coeffsAVX2, coeffsAVX2Out)

		for i := 0; i < N; i++ {
			if cmplx.Abs(coeffs[i]-coeffsAVX2Out[i]) > eps {
				t.Fatalf("FFT: %v != %v", coeffs[i], coeffsAVX2Out[i])
			}
		}
	})

	t.Run("InvFFT", func(t *testing.T) {
		vec.CmplxToFloat4Assign(coeffs, coeffsAVX2)
		invFFTInPlaceRef(coeffs, wNjInvRef)

		invFFTInPlace(coeffsAVX2, wNjInv)
		vec.Float4ToCmplxAssign(coeffsAVX2, coeffsAVX2Out)

		for i := 0; i < N; i++ {
			if cmplx.Abs(coeffs[i]-coeffsAVX2Out[i]) > eps {
				t.Fatalf("InvFFT: %v != %v", coeffs[i], coeffsAVX2Out[i])
			}
		}
	})
}

func BenchmarkFFTAssembly(b *testing.B) {
	N := 1 << 15

	coeffs := make([]complex128, N)
	for i := 0; i < N; i++ {
		coeffs[i] = complex(rand.NormFloat64(), rand.NormFloat64())
	}
	coeffsAVX2 := vec.CmplxToFloat4(coeffs)

	wNjRef := make([]complex128, N/2)
	wNjInvRef := make([]complex128, N/2)
	for j := 0; j < N/2; j++ {
		e := -2 * math.Pi * float64(j) / float64(N)
		wNjRef[j] = cmplx.Exp(complex(0, e))
		wNjInvRef[j] = cmplx.Exp(-complex(0, e))
	}
	vec.BitReverseInPlace(wNjRef)
	vec.BitReverseInPlace(wNjInvRef)

	wNj, wNjInv := genTwiddleFactors(N)

	b.Run("FFT", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			fftInPlaceRef(coeffs, wNjRef)
		}
	})

	b.Run("FFTAVX2", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			fftInPlace(coeffsAVX2, wNj)
		}
	})

	b.Run("InvFFT", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			invFFTInPlaceRef(coeffs, wNjInvRef)
		}
	})

	b.Run("InvFFTAVX2", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			invFFTInPlace(coeffsAVX2, wNjInv)
		}
	})
}
