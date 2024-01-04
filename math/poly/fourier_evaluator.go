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
	// Unlike other complex128 slices, wNj is in natural order.
	wNj []complex128
	// wNjInv holds the inverse twiddle factors exp(2pi*j/N) where j = 0 ~ N/2,
	// ordered in bit-reversed order.
	// Unlike other complex128 slices, wNjInv is in natural order.
	wNjInv []complex128
	// w4Nj holds the twisting factors exp(pi*j/N) where j = 0 ~ N/2.
	// Ordered as float4 representation.
	w4Nj []float64
	// w4NjScaled holds the scaled twisting factors w4Nj / maxT.
	// Ordered as float4 representation.
	w4NjScaled []float64
	// w4NjInv holds the inverse twisting factors exp(-pi*j/N) where j = 0 ~ N/2.
	// Ordered as float4 representation.
	w4NjInv []float64
	// w4NjMono holds the twisting factors for monomials: exp(-pi*j/N) where j = 0 ~ 2N.
	// Unlike other complex128 slices, w4NjMono is in natural order.
	w4NjMono []complex128
	// revMonoIdx holds the precomputed bit-reversed index for MonomialToFourierPoly.
	// Equivalent to BitReverse([-1, 3, 7, ..., 2N-1]).
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

	wNj, wNjInv := genTwiddleFactors(N / 2)

	w4Nj, w4NjInv := genTwistingFactors(N / 2)
	w4NjScaled := vec.ScalarMul(w4Nj, 1/maxT)

	w4NjMono := make([]complex128, 2*N)
	for j := 0; j < 2*N; j++ {
		e := -math.Pi * float64(j) / float64(N)
		w4NjMono[j] = cmplx.Exp(complex(0, e))
	}

	revMonoIdx := make([]int, N/2)
	revMonoIdx[0] = 2*N - 1
	for i := 1; i < N/2; i++ {
		revMonoIdx[i] = 4*i - 1
	}
	vec.BitReverseInPlace(revMonoIdx)

	return &FourierEvaluator[T]{
		degree: N,
		maxT:   maxT,

		wNj:        wNj,
		wNjInv:     wNjInv,
		w4Nj:       w4Nj,
		w4NjScaled: w4NjScaled,
		w4NjInv:    w4NjInv,
		w4NjMono:   w4NjMono,
		revMonoIdx: revMonoIdx,

		buffer: newFourierBuffer[T](N),
	}
}

// genTwiddleFactors generates twiddle factors for FFT.
func genTwiddleFactors(N int) (wNj, wNjInv []complex128) {
	wNjRef := make([]complex128, N/2)
	wNjInvRef := make([]complex128, N/2)
	for j := 0; j < N/2; j++ {
		e := -2 * math.Pi * float64(j) / float64(N)
		wNjRef[j] = cmplx.Exp(complex(0, e))
		wNjInvRef[j] = cmplx.Exp(-complex(0, e))
	}
	vec.BitReverseInPlace(wNjRef)
	vec.BitReverseInPlace(wNjInvRef)

	wNj = make([]complex128, N)
	wNjInv = make([]complex128, N)

	w := 0
	for m := 1; m < N; m <<= 1 {
		for i := 0; i < m; i++ {
			wNj[w] = wNjRef[i]
			w++
		}
	}

	w = 0
	for m := N; m > 1; m >>= 1 {
		for i := 0; i < m/2; i++ {
			wNjInv[w] = wNjInvRef[i]
			w++
		}
	}

	return wNj, wNjInv
}

// genTwistingFactors generates twisting factors for FFT.
func genTwistingFactors(N int) (w4Nj, w4NjInv []float64) {
	w4NjCmplx := make([]complex128, N)
	w4NjInvCmplx := make([]complex128, N)
	for j := 0; j < N; j++ {
		e := 2 * math.Pi * float64(j) / float64(4*N)
		w4NjCmplx[j] = cmplx.Exp(complex(0, e))
		w4NjInvCmplx[j] = cmplx.Exp(-complex(0, e)) / complex(float64(N), 0)
	}
	return vec.CmplxToFloat4(w4NjCmplx), vec.CmplxToFloat4(w4NjInvCmplx)
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
		w4Nj:       f.w4Nj,
		w4NjScaled: f.w4NjScaled,
		w4NjInv:    f.w4NjInv,
		w4NjMono:   f.w4NjMono,
		revMonoIdx: f.revMonoIdx,

		buffer: newFourierBuffer[T](f.degree),
	}
}

// Degree returns the degree of polynomial that the evaluator can handle.
func (f *FourierEvaluator[T]) Degree() int {
	return f.degree
}

// NewFourierPoly creates a new fourier polynomial with the same degree as the evaluator.
func (f *FourierEvaluator[T]) NewFourierPoly() FourierPoly {
	return FourierPoly{Coeffs: make([]float64, f.degree)}
}
