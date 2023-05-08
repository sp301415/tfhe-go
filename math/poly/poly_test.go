package poly_test

import (
	"testing"

	"github.com/sp301415/tfhe/math/poly"
	"github.com/sp301415/tfhe/math/rand"
)

// Prevent compiler optimizations
var res poly.Poly[uint64]
var resFourier poly.FourierPoly

// We benchmark some hot paths here
func BenchmarkPolyMul(b *testing.B) {
	N := 2048

	res = poly.New[uint64](N)
	resFourier = poly.NewFourierPoly(N)

	p0 := poly.New[uint64](N)
	p1 := poly.New[uint64](N)

	usampler := rand.UniformSampler[uint64]{}
	usampler.SamplePoly(p0)
	usampler.SamplePoly(p1)

	evaluater := poly.NewEvaluater[uint64](N)

	b.Run("FFT", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			evaluater.ToFourierPolyInPlace(p0, resFourier)
		}
	})

	fp0 := evaluater.ToFourierPoly(p0)
	b.Run("InvFFT", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			evaluater.ToStandardPolyInPlace(fp0, res)
		}
	})

	b.Run("Mul", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			evaluater.MulInPlace(p0, p1, res)
		}
	})
}
