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

	eval = poly.NewEvaluater[uint64](N)
	fft  = poly.NewFourierTransformer[uint64](N)

	sampler = csprng.NewUniformSamplerWithSeed[uint64](nil)
)

func BenchmarkOperations(b *testing.B) {
	p0 := sampler.SamplePoly(N)
	p1 := sampler.SamplePoly(N)

	b.Run("Add", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			eval.AddInPlace(p0, p1, pOut)
		}
	})

	b.Run("Mul", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			eval.MulInPlace(p0, p1, pOut)
		}
	})

	b.Run("ScalarMul", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			eval.ScalarMulInPlace(p0, 512, pOut)
		}
	})

	b.Run("MonomialMul", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			eval.MonomialMulInPlace(p0, 32, pOut)
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
			fft.MulInPlace(fp0, fp1, fpOut)
		}
	})

	b.Run("FourierStandardMul", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			fft.MulWithStandardInPlace(fp0, p1, fpOut)
		}
	})
}
