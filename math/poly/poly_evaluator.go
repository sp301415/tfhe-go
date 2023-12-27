package poly

import (
	"github.com/sp301415/tfhe-go/math/num"
)

const (
	// MinDegree is the minimum degree of polynomial that Evaluator can handle.
	// Currently, this is set to 8, because AVX2 implementation of FFT and inverse FFT
	// handles first and last loop separately.
	// This implies that the degree of fourier polynomial should be at least 4,
	// and the degree of standard polynomial should be at least 8.
	MinDegree = 1 << 3
)

// Evaluator calculates polynomial algorithms.
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
type Evaluator[T num.Integer] struct {
	// degree is the degree of polynomial that this evaluator can handle.
	degree int

	buffer evaluationBuffer[T]
}

// evaluationBuffer contains buffer values for Evaluator.
type evaluationBuffer[T num.Integer] struct {
	// pOut holds the intermediate polynomial in MulAdd or MulSub type operations.
	pOut Poly[T]
}

// NewEvaluator creates a new Evaluator with degree N.
// N should be power of two, and at least MinDegree.
// Otherwise, it panics.
func NewEvaluator[T num.Integer](N int) *Evaluator[T] {
	if !num.IsPowerOfTwo(N) {
		panic("degree not power of two")
	}

	if N < MinDegree {
		panic("degree smaller than MinDegree")
	}

	return &Evaluator[T]{
		degree: N,

		buffer: newEvaluationBuffer[T](N),
	}
}

// newEvaluationBuffer allocates an empty evaluation buffer.
func newEvaluationBuffer[T num.Integer](N int) evaluationBuffer[T] {
	return evaluationBuffer[T]{
		pOut: NewPoly[T](N),
	}
}

// ShallowCopy returns a shallow copy of this Evaluator.
// Returned Evaluator is safe for concurrent use.
func (e *Evaluator[T]) ShallowCopy() *Evaluator[T] {
	return &Evaluator[T]{
		degree: e.degree,

		buffer: newEvaluationBuffer[T](e.degree),
	}
}

// Degree returns the degree of polynomial that the evaluator can handle.
func (e *Evaluator[T]) Degree() int {
	return e.degree
}

// NewPoly creates a new polynomial with the same degree as the evaluator.
func (e *Evaluator[T]) NewPoly() Poly[T] {
	return Poly[T]{Coeffs: make([]T, e.degree)}
}
