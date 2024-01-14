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
//   - Add(fp0, fp1) adds fp0, fp1, allocates a new polynomial to store the result and returns it.
//   - AddAssign(fp0, fp1, fpOut) adds fp0, fp1 and writes the result to pre-allocated pOut without returning.
//
// Note that in most cases, fp0, fp1, and fpOut can overlap.
// However, for operations that cannot, InPlace methods are implemented separately.
//
// For performance reasons, most methods in this package don't implement bound checks.
// If length mismatch happens, it may panic or produce wrong results.
type FourierEvaluator[T num.Integer] struct {
	// degree is the degree of polynomial that this transformer can handle.
	degree int
	// maxT is a float64 value of MaxT.
	maxT float64

	// wNj holds the twiddle factors for fourier transform.
	// This is stored as "long" form, so that access to the factors are contiguous.
	// Unlike other complex128 slices, wNj is in natural representation.
	wNj []complex128
	// wNjInv holds the twiddle factors for inverse fourier transform.
	// This is stored as "long" form, so that access to the factors are contiguous.
	// Unlike other complex128 slices, wNjInv is in natural representation.
	wNjInv []complex128
	// w4NjMono holds the twiddle factors for monomial fourier transform.
	// Unlike other complex128 slices, w4NjMono is in natural representation.
	w4NjMono []complex128
	// revMonoIdx holds the precomputed bit-reversed index for monomial fourier transform.
	// Equivalent to BitReverse([-1, 3, 7, ..., 2N-1]).
	revMonoIdx []int

	// buffer holds the buffer values for this FourierEvaluator.
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

	logN := num.Log2(N)
	w4Nj := make([]complex128, logN)
	w4NjInv := make([]complex128, logN)
	for j := 0; j < logN; j++ {
		e := 2 * math.Pi * math.Exp2(float64(j)) / float64(4*N)
		w4Nj[j] = cmplx.Exp(complex(0, e))
		w4NjInv[j] = cmplx.Exp(-complex(0, e))
	}

	wNj = make([]complex128, N)
	wNjInv = make([]complex128, N)

	w := 0
	t := logN
	for m := 1; m < N; m <<= 1 {
		t--
		for i := 0; i < m; i++ {
			wNj[w] = wNjRef[i] * w4Nj[t]
			w++
		}
	}

	w = 0
	t = 0
	for m := N; m > 1; m >>= 1 {
		for i := 0; i < m/2; i++ {
			wNjInv[w] = wNjInvRef[i] * w4NjInv[t]
			w++
		}
		t++
	}
	wNjInv[w-1] /= complex(float64(N), 0)

	return wNj, wNjInv
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
