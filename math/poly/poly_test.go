package poly_test

import (
	"testing"

	"github.com/sp301415/tfhe/math/csprng"
	"github.com/sp301415/tfhe/math/poly"
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

	b.Run("Mul", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			eval.MulAssign(p0, p1, pOut)
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

	b.Run("MulAdd", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			eval.MulAddAssign(p0, p1, pOut)
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
