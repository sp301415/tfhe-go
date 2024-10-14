package poly_test

import (
	"fmt"
	"math"
	"math/rand"
	"testing"

	"github.com/sp301415/tfhe-go/math/poly"
)

var (
	LogN = []int{9, 10, 11, 12, 13, 14, 15}
)

func BenchmarkOps(b *testing.B) {
	for _, logN := range LogN {
		N := 1 << logN

		pev := poly.NewEvaluator[uint64](N)

		p0 := pev.NewPoly()
		p1 := pev.NewPoly()
		pOut := pev.NewPoly()

		for i := 0; i < pev.Degree(); i++ {
			p0.Coeffs[i] = rand.Uint64()
			p1.Coeffs[i] = rand.Uint64()
		}

		b.Run(fmt.Sprintf("op=N=%v/Add", N), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				pev.AddPolyAssign(p0, p1, pOut)
			}
		})

		b.Run(fmt.Sprintf("op=N=%v/Sub", N), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				pev.SubPolyAssign(p0, p1, pOut)
			}
		})

		b.Run(fmt.Sprintf("op=N=%v/Mul", N), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				pev.MulPolyAssign(p0, p1, pOut)
			}
		})
	}
}

func BenchmarkFourierOps(b *testing.B) {
	for _, logN := range LogN {
		N := 1 << logN

		pev := poly.NewEvaluator[uint64](N)

		fp0 := pev.NewFourierPoly()
		fp1 := pev.NewFourierPoly()
		fpOut := pev.NewFourierPoly()

		for i := 0; i < pev.Degree(); i++ {
			fp0.Coeffs[i] = (2*rand.Float64() - 1.0) * math.Exp(63)
			fp1.Coeffs[i] = (2*rand.Float64() - 1.0) * math.Exp(63)
		}

		b.Run(fmt.Sprintf("N=%v/op=Add", N), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				pev.AddFourierPolyAssign(fp0, fp1, fpOut)
			}
		})

		b.Run(fmt.Sprintf("N=%v/op=Sub", N), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				pev.SubFourierPolyAssign(fp0, fp1, fpOut)
			}
		})

		b.Run(fmt.Sprintf("N=%v/op=Mul", N), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				pev.MulFourierPolyAssign(fp0, fp1, fpOut)
			}
		})
	}
}

func BenchmarkFourierTransform(b *testing.B) {
	for _, nLog := range LogN {
		N := 1 << nLog

		pev := poly.NewEvaluator[uint64](N)

		p := pev.NewPoly()
		fp := pev.NewFourierPoly()

		for i := 0; i < pev.Degree(); i++ {
			p.Coeffs[i] = rand.Uint64()
		}

		b.Run(fmt.Sprintf("N=%v/op=ToFourierPoly", N), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				pev.ToFourierPolyAssign(p, fp)
			}
		})

		x := N / 3
		b.Run(fmt.Sprintf("N=%v/op=MonomialToFourierPoly", N), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				pev.MonomialToFourierPolyAssign(x, fp)
			}
		})

		b.Run(fmt.Sprintf("N=%v/op=ToPoly", N), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				pev.ToPolyAssignUnsafe(fp, p)
			}
		})
	}
}
