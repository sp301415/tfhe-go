package poly

import (
	"math"
	"math/cmplx"

	"github.com/sp301415/tfhe/math/num"
	"golang.org/x/exp/constraints"
	"gonum.org/v1/gonum/dsp/fourier"
)

// Evaluater calculates polynomial algorithms.
// Most operations have three formats: For example, for Add,
//
//   - Add(p0, p1) returns a new polynomial p = p0 + p1.
//   - AddInPlace(p0, p1, pOut) overrides pOut as p0 + p1.
//   - AddAssign(p0, pOut) overrides pOut as pOut + p0.
type Evaluater[T constraints.Integer] struct {
	// degree is the degree of polynomial that this evaluater can handle.
	degree int

	// fft holds gonum's fourier.FFT.
	fft *fourier.FFT
	// fftHalf holds gonum's fourier.CmplxFFT for N/2. Used for negacyclic convolution.
	fftHalf *fourier.CmplxFFT

	// wj holds the precomputed values of w_2N^j where j = 0 ~ N.
	wj []complex128
	// wjInv holds the precomputed values of w_2N^-j where j = 0 ~ N.
	wjInv []complex128

	/* Buffers */

	// buffFP0 holds the fourier polynomial of p0.
	buffFP0 FourierPoly
	// buffFP1 holds the fourier polynomial of p1.
	buffFP1 FourierPoly
	// buffFPOut holds the fourier polynomial of pOut.
	buffFPOut FourierPoly
	// buffInvFP holds the untwisted/unfolded/InvFFT-applied fourier polynomial
	// while converting fourier polynomial to standard polynomial.
	buffInvFP FourierPoly
	// buffPOut holds the intermediate standard polynomial
	// for MulAdd or MulSub operations.
	buffPOut Poly[T]
}

// NewEvaluater creates a new Evaluater with degree N.
// N should be power of two.
func NewEvaluater[T constraints.Integer](N int) Evaluater[T] {
	if !num.IsPowerOfTwo(N) {
		panic("degree should be power of two")
	}

	wj := make([]complex128, N)
	wjInv := make([]complex128, N)
	for j := 0; j < N/2; j++ {
		e := math.Pi * float64(j) / float64(N)
		wj[j] = cmplx.Exp(complex(0, e))
		wjInv[j] = cmplx.Exp(-complex(0, e))
	}

	return Evaluater[T]{
		degree:  N,
		fft:     fourier.NewFFT(N),
		fftHalf: fourier.NewCmplxFFT(N / 2),

		wj:    wj,
		wjInv: wjInv,

		buffFP0:   NewFourierPoly(N),
		buffFP1:   NewFourierPoly(N),
		buffFPOut: NewFourierPoly(N),
		buffInvFP: NewFourierPoly(N),
		buffPOut:  New[T](N),
	}
}

// Degree returns the degree of polynomial that the evaluater can handle.
func (e Evaluater[T]) Degree() int {
	return e.degree
}
