package poly

import (
	"math"
	"math/cmplx"

	"github.com/sp301415/tfhe-go/math/num"
	"github.com/sp301415/tfhe-go/math/vec"
)

// FourierEvaluator computes polynomial algorithms over the fourier domain.
//
// Operations usually take two forms: for example,
//   - Add(fp0, fp1) adds fp0, fp1, allocates a new polynomial to store the result and returns it.
//   - AddAssign(fp0, fp1, fpOut) adds fp0, fp1 and writes the result to pre-allocated fpOut without returning.
//
// Note that in most cases, fp0, fp1, and fpOut can overlap.
// However, for operations that cannot, InPlace methods are implemented separately.
//
// For performance reasons, most methods in this package don't implement bound checks.
// If length mismatch happens, it may panic or produce wrong results.
type FourierEvaluator[T num.Integer] struct {
	// degree is the degree of polynomial that this transformer can handle.
	degree int
	// q is a float64 value of Q.
	q float64
	// qInv is a float64 value of 1/Q.
	qInv float64

	// tw holds the twiddle factors for fourier transform.
	// This is stored as "long" form, so that access to the factors are contiguous.
	// Unlike other complex128 slices, tw is in natural representation.
	tw []complex128
	// twInv holds the twiddle factors for inverse fourier transform.
	// This is stored as "long" form, so that access to the factors are contiguous.
	// Unlike other complex128 slices, twInv is in natural representation.
	twInv []complex128
	// twMono holds the twiddle factors for monomial fourier transform.
	// Unlike other complex128 slices, twMono is in natural representation.
	twMono []complex128
	// twMonoIdx holds the precomputed bit-reversed index for monomial fourier transform.
	// Equivalent to BitReverse([-1, 3, 7, ..., 2N-1]).
	twMonoIdx []int

	// buffer holds the buffer values for this FourierEvaluator.
	buffer fourierBuffer[T]
}

// fourierBuffer contains buffer values for FourierEvaluator.
type fourierBuffer[T num.Integer] struct {
	// fp holds the FFT value of p.
	fp FourierPoly
	// fpInv holds the InvFFT value of fp.
	fpInv FourierPoly

	// fpMul holds the FFT value of p in multiplication.
	fpMul FourierPoly

	// pSplit holds the split value of p in [*FourierEvaluator.PolyMulBinary].
	pSplit Poly[T]
	// fpSplit holds the fourier transformed pSplit.
	fpSplit FourierPoly
}

// NewFourierEvaluator allocates an empty FourierEvaluator with degree N.
//
// Panics when N is not a power of two, or when N is smaller than MinDegree or larger than MaxDegree.
func NewFourierEvaluator[T num.Integer](N int) *FourierEvaluator[T] {
	switch {
	case !num.IsPowerOfTwo(N):
		panic("degree not power of two")
	case N < MinDegree:
		panic("degree smaller than MinDegree")
	case N > MaxDegree:
		panic("degree larger than MaxDegree")
	}

	Q := math.Exp2(float64(num.SizeT[T]()))
	QInv := math.Exp2(-float64(num.SizeT[T]()))

	tw, twInv := genTwiddleFactors(N / 2)

	twMono := make([]complex128, 2*N)
	for j := 0; j < 2*N; j++ {
		e := -math.Pi * float64(j) / float64(N)
		twMono[j] = cmplx.Exp(complex(0, e))
	}

	twMonoIdx := make([]int, N/2)
	twMonoIdx[0] = 2*N - 1
	for i := 1; i < N/2; i++ {
		twMonoIdx[i] = 4*i - 1
	}
	vec.BitReverseInPlace(twMonoIdx)

	return &FourierEvaluator[T]{
		degree: N,
		q:      Q,
		qInv:   QInv,

		tw:        tw,
		twInv:     twInv,
		twMono:    twMono,
		twMonoIdx: twMonoIdx,

		buffer: newFourierBuffer[T](N),
	}
}

// genTwiddleFactors generates twiddle factors for FFT.
func genTwiddleFactors(N int) (tw, twInv []complex128) {
	wNj := make([]complex128, N/2)
	wNjInv := make([]complex128, N/2)
	for j := 0; j < N/2; j++ {
		e := -2 * math.Pi * float64(j) / float64(N)
		wNj[j] = cmplx.Exp(complex(0, e))
		wNjInv[j] = cmplx.Exp(-complex(0, e))
	}
	vec.BitReverseInPlace(wNj)
	vec.BitReverseInPlace(wNjInv)

	logN := num.Log2(N)
	w4Nj := make([]complex128, logN)
	w4NjInv := make([]complex128, logN)
	for j := 0; j < logN; j++ {
		e := 2 * math.Pi * math.Exp2(float64(j)) / float64(4*N)
		w4Nj[j] = cmplx.Exp(complex(0, e))
		w4NjInv[j] = cmplx.Exp(-complex(0, e))
	}

	tw = make([]complex128, N)
	twInv = make([]complex128, N)

	w, t := 0, logN
	for m := 1; m < N; m <<= 1 {
		t--
		for i := 0; i < m; i++ {
			tw[w] = wNj[i] * w4Nj[t]
			w++
		}
	}

	w, t = 0, 0
	for m := N; m > 1; m >>= 1 {
		for i := 0; i < m/2; i++ {
			twInv[w] = wNjInv[i] * w4NjInv[t]
			w++
		}
		t++
	}
	twInv[w-1] /= complex(float64(N), 0)

	return tw, twInv
}

// newFourierBuffer allocates an empty fourierBuffer.
func newFourierBuffer[T num.Integer](N int) fourierBuffer[T] {
	return fourierBuffer[T]{
		fp:      NewFourierPoly(N),
		fpInv:   NewFourierPoly(N),
		fpMul:   NewFourierPoly(N),
		pSplit:  NewPoly[T](N),
		fpSplit: NewFourierPoly(N),
	}
}

// ShallowCopy returns a shallow copy of this FourierEvaluator.
// Returned FourierEvaluator is safe for concurrent use.
func (f *FourierEvaluator[T]) ShallowCopy() *FourierEvaluator[T] {
	return &FourierEvaluator[T]{
		degree: f.degree,
		q:      f.q,
		qInv:   f.qInv,

		tw:        f.tw,
		twInv:     f.twInv,
		twMono:    f.twMono,
		twMonoIdx: f.twMonoIdx,

		buffer: newFourierBuffer[T](f.degree),
	}
}

// Degree returns the degree of polynomial that the evaluator can handle.
func (f *FourierEvaluator[T]) Degree() int {
	return f.degree
}

// NewPoly allocates an empty polynomial with the same degree as the evaluator.
func (f *FourierEvaluator[T]) NewPoly() Poly[T] {
	return Poly[T]{Coeffs: make([]T, f.degree)}
}

// NewFourierPoly allocates an empty fourier polynomial with the same degree as the evaluator.
func (f *FourierEvaluator[T]) NewFourierPoly() FourierPoly {
	return FourierPoly{Coeffs: make([]float64, f.degree)}
}
