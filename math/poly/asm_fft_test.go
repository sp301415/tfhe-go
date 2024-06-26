package poly

import (
	"math"
	"math/cmplx"
	"math/rand"
	"testing"

	"github.com/sp301415/tfhe-go/math/vec"
)

func fftInPlaceRef(coeffs, tw []complex128) {
	N := len(coeffs)

	t := N
	for m := 1; m < N; m <<= 1 {
		t >>= 1
		for i := 0; i < m; i++ {
			j1 := i * t << 1
			j2 := j1 + t
			for j := j1; j < j2; j++ {
				U, V := coeffs[j], coeffs[j+t]*tw[i]
				coeffs[j], coeffs[j+t] = U+V, U-V
			}
		}
	}
}

func invFFTInPlaceRef(coeffs, twInv []complex128) {
	N := len(coeffs)

	t := 1
	for m := N; m > 1; m >>= 1 {
		j1 := 0
		h := m >> 1
		for i := 0; i < h; i++ {
			j2 := j1 + t
			for j := j1; j < j2; j++ {
				U, V := coeffs[j], coeffs[j+t]
				coeffs[j], coeffs[j+t] = U+V, (U-V)*twInv[i]
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

	twRef := make([]complex128, N/2)
	twInvRef := make([]complex128, N/2)
	for j := 0; j < N/2; j++ {
		e := -2 * math.Pi * float64(j) / float64(N)
		twRef[j] = cmplx.Exp(complex(0, e))
		twInvRef[j] = cmplx.Exp(-complex(0, e))
	}
	vec.BitReverseInPlace(twRef)
	vec.BitReverseInPlace(twInvRef)

	twist := make([]complex128, N)
	twistInv := make([]complex128, N)
	for j := 0; j < N; j++ {
		e := 2 * math.Pi * float64(j) / float64(4*N)
		twist[j] = cmplx.Exp(complex(0, e))
		twistInv[j] = cmplx.Exp(-complex(0, e)) / complex(float64(N), 0)
	}

	tw, twInv := genTwiddleFactors(N)

	t.Run("FFT", func(t *testing.T) {
		vec.CmplxToFloat4Assign(coeffs, coeffsAVX2)
		fftInPlace(coeffsAVX2, tw)
		vec.Float4ToCmplxAssign(coeffsAVX2, coeffsAVX2Out)

		vec.ElementWiseMulAssign(coeffs, twist, coeffs)
		fftInPlaceRef(coeffs, twRef)

		for i := 0; i < N; i++ {
			if cmplx.Abs(coeffs[i]-coeffsAVX2Out[i]) > eps {
				t.Fatalf("FFT: %v != %v", coeffs[i], coeffsAVX2Out[i])
			}
		}
	})

	t.Run("InvFFT", func(t *testing.T) {
		vec.CmplxToFloat4Assign(coeffs, coeffsAVX2)
		invFFTInPlace(coeffsAVX2, twInv)
		vec.Float4ToCmplxAssign(coeffsAVX2, coeffsAVX2Out)

		invFFTInPlaceRef(coeffs, twInvRef)
		vec.ElementWiseMulAssign(coeffs, twistInv, coeffs)

		for i := 0; i < N; i++ {
			if cmplx.Abs(coeffs[i]-coeffsAVX2Out[i]) > eps {
				t.Fatalf("InvFFT: %v != %v", coeffs[i], coeffsAVX2Out[i])
			}
		}
	})
}
