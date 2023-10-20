package poly

import (
	"math"
	"math/cmplx"

	"github.com/sp301415/tfhe-go/math/num"
	"github.com/sp301415/tfhe-go/math/vec"
)

// FourierEvaluator calculates algorithms related to FFT,
// most notably the polynomial multiplication.
//
// While FFT is much faster than Evaluator's karatsuba multiplication,
// in TFHE it is used sparsely because of float64 precision.
//
// Operations usually take two forms: for example,
//   - Add(p0, p1) is equivalent to var p = p0 + p1.
//   - AddAssign(p0, p1, pOut) is equivalent to pOut = p0 + p1.
//
// Note that usually calling Assign(p0, pOut, pOut) is valid.
// However, for some operations, InPlace methods are implemented separately.
//
// # Warning
//
// For performance reasons, functions in this package usually don't implement bound checks.
// If length mismatch happens, usually the result is wrong.
type FourierEvaluator[T num.Integer] struct {
	// degree is the degree of polynomial that this transformer can handle.
	degree int
	// maxT is a float64 value of 2^sizeT.
	maxT float64

	// wNj holds the precomputed values of w_N^j where j = 0 ~ N/2,
	// ordered in bit-reversed order.
	wNj []complex128
	// wNjInv holds the precomputed values of w_N^-j where j = 0 ~ N/2,
	// ordered in bit-reversed order.
	wNjInv []complex128
	// w2Nj holds the precomputed values of w_2N^j where j = 0 ~ N/2.
	w2Nj []complex128
	// w2NjInv holds the precomputed values of scaled w_2N^-j / (N / 2) where j = 0 ~ N/2.
	w2NjInv []complex128

	buffer fourierBuffer[T]
}

// fourierBuffer contains buffer values for FourierEvaluator.
type fourierBuffer[T num.Integer] struct {
	// fp holds the FFT value of p.
	fp FourierPoly
	// fpInv holds the InvFFT value of fp.
	fpInv FourierPoly
}

// NewFourierEvaluator creates a new FourierEvaluator with degree N.
// N should be power of two.
func NewFourierEvaluator[T num.Integer](N int) *FourierEvaluator[T] {
	if !num.IsPowerOfTwo(N) {
		panic("degree should be power of two")
	}

	wNj := make([]complex128, N/2)
	wNjInv := make([]complex128, N/2)
	for j := 0; j < N/2; j++ {
		e := 2 * math.Pi * float64(j) / float64(N)
		wNj[j] = cmplx.Exp(complex(0, e))
		wNjInv[j] = cmplx.Exp(-complex(0, e))
	}
	vec.BitReverseInPlace(wNj)
	vec.BitReverseInPlace(wNjInv)

	w2Nj := make([]complex128, N/2)
	w2NjInv := make([]complex128, N/2)
	for j := 0; j < N/2; j++ {
		e := math.Pi * float64(j) / float64(N)
		w2Nj[j] = cmplx.Exp(complex(0, e))
		w2NjInv[j] = cmplx.Exp(-complex(0, e)) / complex(float64(N/2), 0)
	}

	return &FourierEvaluator[T]{
		degree: N,
		maxT:   math.Exp2(float64(num.SizeT[T]())),

		wNj:     wNj,
		wNjInv:  wNjInv,
		w2Nj:    w2Nj,
		w2NjInv: w2NjInv,

		buffer: newFourierBuffer[T](N),
	}
}

// newFourierBuffer allocates an empty fourierBuffer.
func newFourierBuffer[T num.Integer](N int) fourierBuffer[T] {
	return fourierBuffer[T]{
		fp:    NewFourierPoly(N),
		fpInv: NewFourierPoly(N),
	}
}

// ShallowCopy returns a shallow copy of this FourierEvaluator.
// Returned FourierEvaluator is safe for concurrent use.
func (f *FourierEvaluator[T]) ShallowCopy() *FourierEvaluator[T] {
	return &FourierEvaluator[T]{
		degree: f.degree,
		maxT:   f.maxT,

		wNj:     f.wNj,
		wNjInv:  f.wNjInv,
		w2Nj:    f.w2Nj,
		w2NjInv: f.w2NjInv,

		buffer: newFourierBuffer[T](f.degree),
	}
}

// Degree returns the degree of polynomial that the evaluator can handle.
func (e *FourierEvaluator[T]) Degree() int {
	return e.degree
}

// NewFourierPoly creates a new fourier polynomial with the same degree as the evaluator.
func (e *FourierEvaluator[T]) NewFourierPoly() FourierPoly {
	return FourierPoly{Coeffs: make([]complex128, e.degree/2)}
}
