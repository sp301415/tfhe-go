package poly_test

import (
	"testing"

	"github.com/sp301415/tfhe/math/poly"
	"github.com/sp301415/tfhe/math/rand"
)

type T = uint64

var (
	N    = 1 << 10
	pOut = poly.New[T](N)
	eval = poly.NewEvaluater[T](N)
)

func BenchmarkOperations(b *testing.B) {
	sampler := rand.NewUniformSamplerWithSeed[T](nil)

	p0 := sampler.SamplePoly(N)
	p1 := sampler.SamplePoly(N)

	b.Run("Add", func(b *testing.B) {
		eval.AddInPlace(p0, p1, pOut)
	})

	b.Run("Mul", func(b *testing.B) {
		eval.MulInPlace(p0, p1, pOut)
	})

	b.Run("ScalarMul", func(b *testing.B) {
		eval.ScalarMulInPlace(p0, 512, pOut)
	})

	b.Run("MonomialMul", func(b *testing.B) {
		eval.MonomialMulInPlace(p0, 512, 32, pOut)
	})

	b.Run("MulAdd", func(b *testing.B) {
		eval.MulAddAssign(p0, p1, pOut)
	})
}
