package poly

import (
	"github.com/sp301415/tfhe/math/num"
)

// Evaluater calculates polynomial algorithms.
// Operations usually take three forms: for example,
//   - Add(p0, p1) is equivalent to var p = p0 + p1
//   - AddInPlace(p0, p1, pOut) is equivalent to pOut = p0 + p1
//   - AddAssign(p0, pOut) is equivalent to pOut += p0
type Evaluater[T num.Integer] struct {
	// degree is the degree of polynomial that this evaluater can handle.
	degree int

	buffer evaluationBuffer[T]
}

// evaluationBuffer contains buffer values for Evaluater.
type evaluationBuffer[T num.Integer] struct {
	// karatsubaBuffer holds the intermediate buffers used in karatsuba multiplication.
	// Each buffer can be indexed as ((3^depth - 1)/2) + index. (I know, right?)
	karatsubaBuffer []karatsubaBuffer[T]

	// pOut holds the intermediate polynomial in MulAssign, MulAdd or MulSub type operations.
	// This may take aditional O(N) loop, but the multiplication itself is a dominating factor,
	// so it doesn't matter.
	pOut Poly[T]
}

// NewEvaluater creates a new Evaluater with degree N.
// N should be power of two.
func NewEvaluater[T num.Integer](N int) Evaluater[T] {
	if !num.IsPowerOfTwo(N) {
		panic("degree should be power of two")
	}

	return Evaluater[T]{
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

// ShallowCopy returns a shallow copy of this Evaluater.
// Returned Evaluater is safe for concurrent use.
func (e Evaluater[T]) ShallowCopy() Evaluater[T] {
	return Evaluater[T]{
		degree: e.degree,

		buffer: newEvaluationBuffer[T](e.degree),
	}
}

// Degree returns the degree of polynomial that the evaluater can handle.
func (e Evaluater[T]) Degree() int {
	return e.degree
}
