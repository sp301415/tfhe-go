package poly

import (
	"math"
	"math/cmplx"

	"github.com/sp301415/tfhe/math/num"
	"golang.org/x/exp/constraints"
	"gonum.org/v1/gonum/dsp/fourier"
)

// Evaluater calculates polynomial algorithms.
// Operations usually take three forms: for example,
//   - Add(p0, p1) is equivalent to var p = p0 + p1
//   - AddInPlace(p0, p1, pOut) is equivalent to pOut = p0 + p1
//   - AddAssign(p0, pOut) is equivalent to pOut += p0
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

	buffer evaluationBuffer[T]
}

// evaluationBuffer contains buffer values for Evaluater.
type evaluationBuffer[T constraints.Integer] struct {
	// fp0 holds the fourier polynomial of p0.
	fp0 FourierPoly
	// fp1 holds the fourier polynomial of p1.
	fp1 FourierPoly
	// fpOut holds the fourier polynomial of pOut.
	fpOut FourierPoly
	// fpInv holds the InvFTT & Untwisted & Unfolded value of fp.
	fpInv FourierPoly
	// pOut holds the result polynomial in MulAdd or MulSub operations.
	pOut Poly[T]
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

		buffer: newEvaluationBuffer[T](N),
	}
}

// newEvaluationBuffer allocates an empty evaluation buffer.
func newEvaluationBuffer[T constraints.Integer](N int) evaluationBuffer[T] {
	return evaluationBuffer[T]{
		fp0:   NewFourierPoly(N),
		fp1:   NewFourierPoly(N),
		fpOut: NewFourierPoly(N),
		fpInv: NewFourierPoly(N),
		pOut:  New[T](N),
	}
}

// ShallowCopy returns a shallow copy of this Evaluater.
// Returned Evaluater is safe for concurrent use.
func (e Evaluater[T]) ShallowCopy() Evaluater[T] {
	return Evaluater[T]{
		degree: e.degree,

		fft:     fourier.NewFFT(e.degree),
		fftHalf: fourier.NewCmplxFFT(e.degree / 2),

		wj:    e.wj,
		wjInv: e.wjInv,

		buffer: newEvaluationBuffer[T](e.degree),
	}
}

// Degree returns the degree of polynomial that the evaluater can handle.
func (e Evaluater[T]) Degree() int {
	return e.degree
}
