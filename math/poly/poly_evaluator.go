package poly

import (
	"github.com/sp301415/tfhe-go/math/num"
)

const (
	// MinDegree is the minimum degree of polynomial that Evaluator can handle.
	// Currently, this is set to 8, because AVX2 implementation of FFT and inverse FFT
	// handles first and last loop seperately.
	// This implies that the degree of fourier polynomial should be at least 4,
	// and the degree of standard polynomial should be at least 8.
	MinDegree = 8
)

// Evaluator calculates polynomial algorithms.
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
		pOut: New[T](N),
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
