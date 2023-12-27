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
// Operations usually take two forms: for example,
//   - Add(p0, p1) adds p0, p1, allocates a new polynomial to store the result, and returns it.
//   - AddAssign(p0, p1, pOut) adds p0, p1, and writes the result to pre-existing pOut without returning.
//
// Note that in most cases, p0, p1, and pOut can overlap.
// However, for operations that cannot, InPlace methods are implemented separately.
//
// For performance reasons, most methods in this package don't implement bound checks.
// If length mismatch happens, it may panic or produce wrong results.
type FourierEvaluator[T num.Integer] struct {
	// degree is the degree of polynomial that this transformer can handle.
	degree int
	// maxT is a float64 value of MaxT.
	maxT float64

	// wNj holds the twiddle factors exp(-2pi*j/N) where j = 0 ~ N/2,
	// ordered in bit-reversed order.
	wNj []complex128
	// wNjInv holds the inverse twiddle factors exp(2pi*j/N) where j = 0 ~ N/2,
	// ordered in bit-reversed order.
	wNjInv []complex128
	// w2Nj holds the twisting factors exp(pi*j/N) where j = 0 ~ N/2.
	w2Nj []complex128
	// w2NjScaled holds the scaled twisting factors w2Nj * maxT.
	w2NjScaled []complex128
	// w2NjInv holds the inverse twisting factors exp(-pi*j/N) where j = 0 ~ N/2.
	w2NjInv []complex128
	// w2NjMono holds the twisting factors for monomials: exp(-pi*j/N) where j = 0 ~ 2N.
	w2NjMono []complex128
	// revMonoIdx holds the precomputed bit-reversed index for MonomialToFourierPoly.
	// Equivalent to BitReverse([1, 5, 9, ..., 4N-1]).
	revMonoIdx []int

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
// N should be power of two, and at least MinDegree.
// Otherwise, it panics.
func NewFourierEvaluator[T num.Integer](N int) *FourierEvaluator[T] {
	if !num.IsPowerOfTwo(N) {
		panic("degree not power of two")
	}

	if N < MinDegree {
		panic("degree smaller than MinDegree")
	}

	maxT := math.Exp2(float64(num.SizeT[T]()))

	wNj := make([]complex128, N/2)
	wNjInv := make([]complex128, N/2)
	for j := 0; j < N/2; j++ {
		e := 2 * math.Pi * float64(j) / float64(N)
		wNj[j] = cmplx.Exp(-complex(0, e))
		wNjInv[j] = cmplx.Exp(complex(0, e))
	}
	vec.BitReverseInPlace(wNj)
	vec.BitReverseInPlace(wNjInv)

	w2Nj := make([]complex128, N/2)
	w2NjScaled := make([]complex128, N/2)
	w2NjInv := make([]complex128, N/2)
	for j := 0; j < N/2; j++ {
		e := math.Pi * float64(j) / float64(N)
		w2Nj[j] = cmplx.Exp(complex(0, e))
		w2NjScaled[j] = w2Nj[j] / complex(maxT, 0)
		w2NjInv[j] = cmplx.Exp(-complex(0, e)) / complex(float64(N/2), 0)
	}

	w2NjMono := make([]complex128, 2*N)
	for j := 0; j < 2*N; j++ {
		e := math.Pi * float64(j) / float64(N)
		w2NjMono[j] = cmplx.Exp(-complex(0, e))
	}

	revOddIdx := make([]int, N/2)
	for i := 0; i < N/2; i++ {
		revOddIdx[i] = 4*i + 1
	}
	vec.BitReverseInPlace(revOddIdx)

	return &FourierEvaluator[T]{
		degree: N,
		maxT:   maxT,

		wNj:        wNj,
		wNjInv:     wNjInv,
		w2Nj:       w2Nj,
		w2NjScaled: w2NjScaled,
		w2NjInv:    w2NjInv,
		w2NjMono:   w2NjMono,
		revMonoIdx: revOddIdx,

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

		wNj:        f.wNj,
		wNjInv:     f.wNjInv,
		w2Nj:       f.w2Nj,
		w2NjScaled: f.w2NjScaled,
		w2NjInv:    f.w2NjInv,
		w2NjMono:   f.w2NjMono,
		revMonoIdx: f.revMonoIdx,

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
