package poly

import (
	"github.com/sp301415/tfhe-go/math/num"
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
	// karatsubaBuffer holds the intermediate buffers used in karatsuba multiplication.
	karatsubaBuffer []karatsubaBuffer[T]

	// pOut holds the intermediate polynomial in MulAdd or MulSub type operations.
	// This may take aditional O(N) loop, but the multiplication itself is a dominating factor,
	// so it doesn't matter.
	pOut Poly[T]
}

// NewEvaluator creates a new Evaluator with degree N.
// N should be power of two.
func NewEvaluator[T num.Integer](N int) *Evaluator[T] {
	if !num.IsPowerOfTwo(N) {
		panic("degree should be power of two")
	}

	return &Evaluator[T]{
		degree: N,

		buffer: newEvaluationBuffer[T](N),
	}
}

// newEvaluationBuffer allocates an empty evaluation buffer.
func newEvaluationBuffer[T num.Integer](N int) evaluationBuffer[T] {
	return evaluationBuffer[T]{
		karatsubaBuffer: newKaratsubaBuffer[T](N),

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
