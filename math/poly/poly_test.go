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
	r := rand.New(rand.NewSource(0))

	for _, logN := range LogN {
		b.Run(fmt.Sprintf("LogN=%v", logN), func(b *testing.B) {
			N := 1 << logN

			pev := poly.NewEvaluator[uint64](N)

			p0 := pev.NewPoly()
			p1 := pev.NewPoly()
			pOut := pev.NewPoly()

			for i := 0; i < pev.Rank(); i++ {
				p0.Coeffs[i] = r.Uint64()
				p1.Coeffs[i] = r.Uint64()
			}

			fp := pev.FwdFFTPoly(p0)

			b.Run("Add", func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					pev.AddPolyTo(pOut, p0, p1)
				}
			})

			b.Run("Sub", func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					pev.SubPolyTo(pOut, p0, p1)
				}
			})

			b.Run("BinaryMul", func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					pev.ShortFFTPolyMulPolyTo(pOut, p0, fp)
				}
			})

			b.Run("Mul", func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					pev.MulPolyTo(pOut, p0, p1)
				}
			})
		})
	}
}

func BenchmarkFFTOps(b *testing.B) {
	r := rand.New(rand.NewSource(0))

	for _, logN := range LogN {
		b.Run(fmt.Sprintf("LogN=%v", logN), func(b *testing.B) {
			N := 1 << logN

			pev := poly.NewEvaluator[uint64](N)

			fp0 := pev.NewFFTPoly()
			fp1 := pev.NewFFTPoly()
			fpOut := pev.NewFFTPoly()

			for i := 0; i < pev.Rank(); i++ {
				fp0.Coeffs[i] = (2*r.Float64() - 1.0) * math.Exp(63)
				fp1.Coeffs[i] = (2*r.Float64() - 1.0) * math.Exp(63)
			}

			b.Run("Add", func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					pev.AddFFTPolyTo(fpOut, fp0, fp1)
				}
			})

			b.Run("Sub", func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					pev.SubFFTPolyTo(fpOut, fp0, fp1)
				}
			})

			b.Run("Mul", func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					pev.MulFFTPolyTo(fpOut, fp0, fp1)
				}
			})
		})
	}
}

func BenchmarkFFT(b *testing.B) {
	r := rand.New(rand.NewSource(0))

	for _, logN := range LogN {
		b.Run(fmt.Sprintf("LogN=%v", logN), func(b *testing.B) {
			N := 1 << logN

			pev := poly.NewEvaluator[uint64](N)

			p := pev.NewPoly()
			fp := pev.NewFFTPoly()

			for i := 0; i < pev.Rank(); i++ {
				p.Coeffs[i] = r.Uint64()
			}

			b.Run("FFT", func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					pev.FwdFFTPolyTo(fp, p)
				}
			})

			x := N / 3
			b.Run("MonomialFFT", func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					pev.MonomialFwdFFTTo(fp, x)
				}
			})

			b.Run("InvFFT", func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					pev.InvFFTToUnsafe(p, fp)
				}
			})
		})
	}
}
