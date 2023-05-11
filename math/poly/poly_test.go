package poly_test

import (
	"math/rand"
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
			eval.MonomialMulInPlace(p0, 512, 32, pOut)
		}
	})

	b.Run("MulAdd", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			eval.MulAddAssign(p0, p1, pOut)
		}
	})

}

func BenchmarkFFT(b *testing.B) {
	p := sampler.SamplePoly(N)

	b.Run("FFT", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			fft.ToScaledFourierPolyInPlace(p, fpOut)
		}
	})

	fp := poly.NewFourierPoly(N)
	for i := range fp.Coeffs {
		fp.Coeffs[i] = complex(rand.Float64(), rand.Float64())
	}

	b.Run("InvFFT", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			fft.ToScaledStandardPolyInPlace(fp, p)
		}
	})
}
