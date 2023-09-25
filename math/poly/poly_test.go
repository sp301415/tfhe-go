package poly_test

import (
	"testing"

	"github.com/sp301415/tfhe-go/math/csprng"
	"github.com/sp301415/tfhe-go/math/poly"
)

var (
	N = 1 << 10

	pOut  = poly.New[uint64](N)
	fpOut = poly.NewFourierPoly(N)

	eval = poly.NewEvaluator[uint64](N)
	fft  = poly.NewFourierTransformer[uint64](N)

	sampler = csprng.NewUniformSamplerWithSeed[uint64](nil)
)

func BenchmarkOperations(b *testing.B) {
	p0 := poly.New[uint64](N)
	p1 := poly.New[uint64](N)
	sampler.SampleSliceAssign(p0.Coeffs)
	sampler.SampleSliceAssign(p1.Coeffs)

	b.Run("Add", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			eval.AddAssign(p0, p1, pOut)
		}
	})

	b.Run("Neg", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			eval.NegAssign(p0, pOut)
		}
	})

	b.Run("ScalarMul", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			eval.ScalarMulAssign(p0, 512, pOut)
		}
	})

	b.Run("MonomialMul", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			eval.MonomialMulAssign(p0, 32, pOut)
		}
	})

	b.Run("Mul", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			eval.MulAssign(p0, p1, pOut)
		}
	})

	fp0 := fft.ToFourierPoly(p0)
	fp1 := fft.ToFourierPoly(p1)

	b.Run("FourierMul", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			fft.MulAssign(fp0, fp1, fpOut)
		}
	})

	b.Run("FourierStandardMul", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			fft.PolyMulAssign(fp0, p1, fpOut)
		}
	})
}

func BenchmarkFFT(b *testing.B) {
	p := poly.New[uint64](N)
	sampler.SampleSliceAssign(p.Coeffs)
	fp := fft.ToFourierPoly(p)

	b.Run("FFT", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			fft.FFTInPlace(fp)
		}
	})

	b.Run("ToFourierPoly", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			fft.ToFourierPolyAssign(p, fpOut)
		}
	})

	b.Run("ToScaledFourierPoly", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			fft.ToScaledFourierPolyAssign(p, fpOut)
		}
	})

	b.Run("InvFFT", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			fft.InvFFTInPlace(fp)
		}
	})

	b.Run("ToStandardPoly", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			fft.ToStandardPolyAssign(fp, pOut)
		}
	})

	b.Run("ToScaledStandardPoly", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			fft.ToScaledStandardPolyAssign(fp, pOut)
		}
	})

}
