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

	// MaxDegree is the maximum degree of polynomial that Evaluator can handle.
	// Currently, the maximum split bits used in [*Evaluator.Mul] is 13.
	// For this split, in degree 2^24, the failure probability is less than 2^-73, which is negligible.
	MaxDegree = 1 << 24
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

	// splitBits is the number of bits to split in [*Evaluator.Mul].
	//
	//	- If sizeT <= 32, splitBits = 11.
	//	- If sizeT = 64, splitBits = 13.
	splitBits T
	// splitCount is the number of splits in [*Evaluator.Mul].
	//
	//	- If sizeT = 8, splitCount = 1.
	//	- If sizeT = 16, splitCount = 2.
	//	- If sizeT = 32, splitCount = 3.
	//	- If sizeT = 64, splitCount = 5.
	splitCount int
	// splitBitsBinary is the number of bits to split in [*Evaluator.BinaryFourierMul].
	//
	//	- If sizeT <= 16, splitBitsBinary = 16.
	//	- If sizeT >= 32, splitBitsBinary = 26.
	splitBitsBinary T
	// splitCountBinary is the number of splits in [*Evaluator.BinaryFourierMul].
	//
	//	- If sizeT <= 16, splitCountBinary = 1.
	//	- If sizeT = 32, splitCountBinary = 2.
	//	- If sizeT = 64, splitCountBinary = 3.
	splitCountBinary int

	// buffer is the buffer values for this Evaluator.
	buffer evaluationBuffer[T]
}

// evaluationBuffer contains buffer values for Evaluator.
type evaluationBuffer[T num.Integer] struct {
	// pOut is the intermediate output polynomial for InPlace operations.
	pOut Poly[T]

	// fp is the FFT value of p.
	fp FourierPoly
	// fpInv is the InvFFT value of fp.
	fpInv FourierPoly

	// pSplit is the split value of p0, p1 in [*Evaluator.Mul].
	pSplit Poly[T]
	// fp0Split is the fourier transformed p0Split.
	fp0Split []FourierPoly
	// fp1Split is the fourier transformed p1Split.
	fp1Split []FourierPoly
	// fpOutSplit is the fourier transformed pOutSplit.
	fpOutSplit []FourierPoly
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

	splitBits, splitCount := genSplitParameters[T]()
	splitBitsBinary, splitCountBinary := genSplitParametersBinary[T]()

	return &Evaluator[T]{
		degree: N,
		q:      Q,
		qInv:   QInv,

		tw:        tw,
		twInv:     twInv,
		twMono:    twMono,
		twMonoIdx: twMonoIdx,

		splitBits:        splitBits,
		splitCount:       splitCount,
		splitBitsBinary:  splitBitsBinary,
		splitCountBinary: splitCountBinary,

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

// genSplitParameters generates splitBits and splitCount for [*Evaluator.MulPoly].
func genSplitParameters[T num.Integer]() (splitBits T, splitCount int) {
	switch num.SizeT[T]() {
	case 8:
		return 11, 1
	case 16:
		return 11, 2
	case 32:
		return 11, 3
	case 64:
		return 13, 5
	}
	return 0, 0
}

// genSplitParametersBinary generates splitBitsBinary and splitCountBinary for [*Evaluator.BinaryFourierMulPoly].
func genSplitParametersBinary[T num.Integer]() (splitBitsBinary T, splitCountBinary int) {
	switch num.SizeT[T]() {
	case 8:
		return 16, 1
	case 16:
		return 16, 1
	case 32:
		return 26, 2
	case 64:
		return 26, 3
	}
	return 0, 0
}

// newFourierBuffer allocates an empty fourierBuffer.
func newFourierBuffer[T num.Integer](N int) evaluationBuffer[T] {
	_, splitCount := genSplitParameters[T]()

	fp0Split := make([]FourierPoly, splitCount)
	fp1Split := make([]FourierPoly, splitCount)
	fpOutSplit := make([]FourierPoly, splitCount)
	for i := 0; i < splitCount; i++ {
		fp0Split[i] = NewFourierPoly(N)
		fp1Split[i] = NewFourierPoly(N)
		fpOutSplit[i] = NewFourierPoly(N)
	}

	return evaluationBuffer[T]{
		pOut: NewPoly[T](N),

		fp:    NewFourierPoly(N),
		fpInv: NewFourierPoly(N),

		pSplit:     NewPoly[T](N),
		fp0Split:   fp0Split,
		fp1Split:   fp1Split,
		fpOutSplit: fpOutSplit,
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

		splitBits:        e.splitBits,
		splitCount:       e.splitCount,
		splitBitsBinary:  e.splitBitsBinary,
		splitCountBinary: e.splitCountBinary,

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
