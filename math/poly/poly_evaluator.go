package poly

import (
	"math"
	"math/cmplx"

	"github.com/sp301415/tfhe-go/math/num"
	"github.com/sp301415/tfhe-go/math/vec"
)

const (
	// MinDegree is the minimum degree of polynomial that Evaluator can handle.
	// Currently, this is set to 16, because AVX2 implementation of FFT and inverse FFT
	// handles first/last two loops separately.
	MinDegree = 1 << 4
)

// Evaluator computes polynomial operations over the N-th cyclotomic ring.
//
// Operations usually take two forms: for example,
//   - Op(p0, p1) adds p0, p1, allocates a new polynomial to store the result and returns it.
//   - OpAssign(p0, p1, pOut) adds p0, p1 and writes the result to pre-allocated pOut without returning.
//
// Note that in most cases, p0, p1, and fpOut can overlap.
// However, for operations that cannot, InPlace methods are implemented separately.
//
// For performance reasons, most methods in this package don't implement bound checks.
// If length mismatch happens, it may panic or produce wrong results.
type Evaluator[T num.Integer] struct {
	// degree is the degree of polynomial that this transformer can handle.
	degree int
	// q is a float64 value of Q.
	q float64
	// qInv is a float64 value of 1/Q.
	qInv float64

	// tw is the twiddle factors for fourier transform.
	// This is stored as "long" form, so that access to the factors are contiguous.
	// Unlike other complex128 slices, tw is in natural representation.
	tw []complex128
	// twInv is the twiddle factors for inverse fourier transform.
	// This is stored as "long" form, so that access to the factors are contiguous.
	// Unlike other complex128 slices, twInv is in natural representation.
	twInv []complex128
	// twMono is the twiddle factors for monomial fourier transform.
	// Unlike other complex128 slices, twMono is in natural representation.
	twMono []complex128
	// twMonoIdx is the precomputed bit-reversed index for monomial fourier transform.
	// Equivalent to BitReverse([-1, 3, 7, ..., 2N-1]).
	twMonoIdx []int

	// buffer is the buffer values for this Evaluator.
	buffer evaluationBuffer[T]
}

// evaluationBuffer contains buffer values for Evaluator.
type evaluationBuffer[T num.Integer] struct {
	// pOut is the intermediate output polynomial for InPlace operations.
	pOut Poly[T]
	// fpOut is the intermediate output fourier polynomial for InPlace operations.
	fpOut FourierPoly

	// fp is the FFT value of p.
	fp FourierPoly
	// fpInv is the InvFFT value of fp.
	fpInv FourierPoly

	// pSplit is the split value of p0 in [*Evaluator.BinaryFourierPolyMulPoly].
	pSplit Poly[T]
	// fpBinarySplit is the fourier transformed pSplit in [*Evaluator.BinaryFourierPolyMulPoly].
	fpBinarySplit []FourierPoly
}

// NewEvaluator allocates an empty Evaluator with degree N.
//
// Panics when N is not a power of two, or when N is smaller than MinDegree or larger than MaxDegree.
func NewEvaluator[T num.Integer](N int) *Evaluator[T] {
	switch {
	case !num.IsPowerOfTwo(N):
		panic("degree not power of two")
	case N < MinDegree:
		panic("degree smaller than MinDegree")
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

	return &Evaluator[T]{
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

// splitParameters generates splitBits and splitCount for [*Evaluator.MulPoly].
func splitParameters[T num.Integer](N int) (splitBits T, splitCount int) {
	splitBits = T(50-num.Log2(N)) / 2
	splitCount = int(math.Ceil(float64(num.SizeT[T]()) / float64(splitBits)))
	return
}

// splitParametersBinary generates splitBits and splitCount for [*Evaluator.BinaryFourierPolyMulPoly].
func splitParametersBinary[T num.Integer](N int) (splitBits T, splitCount int) {
	splitBits = T(50 - num.Log2(N))
	splitCount = int(math.Ceil(float64(num.SizeT[T]()) / float64(splitBits)))
	return
}

// newFourierBuffer allocates an empty fourierBuffer.
func newFourierBuffer[T num.Integer](N int) evaluationBuffer[T] {
	_, splitCount := splitParametersBinary[T](N)

	fpBinarySplit := make([]FourierPoly, splitCount)
	for i := 0; i < splitCount; i++ {
		fpBinarySplit[i] = NewFourierPoly(N)
	}

	return evaluationBuffer[T]{
		pOut:  NewPoly[T](N),
		fpOut: NewFourierPoly(N),

		fp:    NewFourierPoly(N),
		fpInv: NewFourierPoly(N),

		pSplit:        NewPoly[T](N),
		fpBinarySplit: fpBinarySplit,
	}
}

// ShallowCopy returns a shallow copy of this Evaluator.
// Returned Evaluator is safe for concurrent use.
func (e *Evaluator[T]) ShallowCopy() *Evaluator[T] {
	return &Evaluator[T]{
		degree: e.degree,
		q:      e.q,
		qInv:   e.qInv,

		tw:        e.tw,
		twInv:     e.twInv,
		twMono:    e.twMono,
		twMonoIdx: e.twMonoIdx,

		buffer: newFourierBuffer[T](e.degree),
	}
}

// Degree returns the degree of polynomial that the evaluator can handle.
func (e *Evaluator[T]) Degree() int {
	return e.degree
}

// NewPoly allocates an empty polynomial with the same degree as the evaluator.
func (e *Evaluator[T]) NewPoly() Poly[T] {
	return Poly[T]{Coeffs: make([]T, e.degree)}
}

// NewFourierPoly allocates an empty fourier polynomial with the same degree as the evaluator.
func (e *Evaluator[T]) NewFourierPoly() FourierPoly {
	return FourierPoly{Coeffs: make([]float64, e.degree)}
}
