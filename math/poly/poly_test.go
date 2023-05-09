package poly_test

import (
	"testing"

	"github.com/sp301415/tfhe/math/num"
	"github.com/sp301415/tfhe/math/poly"
	"github.com/sp301415/tfhe/math/rand"
)

type T = uint64

var (
	N    = 1 << 16
	pOut = poly.New[T](N)
)

func prepareTestPoly[T num.Integer]() (p0, p1 poly.Poly[T]) {
	var sampler rand.UniformSampler[T]

	p0 = poly.New[T](N)
	p1 = poly.New[T](N)

	sampler.SamplePoly(p0)
	sampler.SamplePoly(p1)

	return
}

func BenchmarkOperations(b *testing.B) {
	eval := poly.NewEvaluater[T](N)
	p0, p1 := prepareTestPoly[T]()

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
