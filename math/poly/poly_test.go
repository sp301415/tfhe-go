package poly_test

import (
	"fmt"
	"math"
	"math/rand"
	"testing"

	"github.com/sp301415/tfhe-go/math/poly"
)

var (
	NLog = []int{9, 10, 11, 12, 13, 14, 15}
)

func BenchmarkFourierOps(b *testing.B) {
	for _, nLog := range NLog {
		N := 1 << nLog

		fft := poly.NewFourierEvaluator[uint64](N)

		fp0 := fft.NewFourierPoly()
		fp1 := fft.NewFourierPoly()
		fpOut := fft.NewFourierPoly()

		for i := 0; i < fft.Degree(); i++ {
			fp0.Coeffs[i] = (2*rand.Float64() - 1.0) * math.Exp(63)
			fp1.Coeffs[i] = (2*rand.Float64() - 1.0) * math.Exp(63)
		}

		b.Run(fmt.Sprintf("Add/%v", N), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				fft.AddAssign(fp0, fp1, fpOut)
			}
		})

		b.Run(fmt.Sprintf("Sub/%v", N), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				fft.SubAssign(fp0, fp1, fpOut)
			}
		})

		b.Run(fmt.Sprintf("Mul/%v", N), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				fft.MulAssign(fp0, fp1, fpOut)
			}
		})
	}
}

func BenchmarkFourierTransform(b *testing.B) {
	for _, nLog := range NLog {
		N := 1 << nLog

		fft := poly.NewFourierEvaluator[uint64](N)

		p := fft.NewPoly()
		fp := fft.NewFourierPoly()

		for i := 0; i < fft.Degree(); i++ {
			p.Coeffs[i] = rand.Uint64()
		}

		b.Run(fmt.Sprintf("ToFourierPoly/%v", N), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				fft.ToFourierPolyAssign(p, fp)
			}
		})

		x := rand.Int() % (2 * N)
		b.Run(fmt.Sprintf("MonomialToFourierPoly/%v", N), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				fft.MonomialToFourierPolyAssign(x, fp)
			}
		})

		b.Run(fmt.Sprintf("ToPoly/%v", N), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				fft.ToPolyAssignUnsafe(fp, p)
			}
		})
	}
}
