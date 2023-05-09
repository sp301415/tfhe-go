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

	buffer evaluaterBuffer[T]
}

// evaluaterBuffer contains buffer values for Evaluater.
type evaluaterBuffer[T num.Integer] struct {
	// karatsubaBuffer holds the intermediate buffers used in karatsuba multiplication.
	// Each buffer can be indexed as ((3^depth - 1)/2) + index. (I know, right?)
	karatsubaBuffer []karatsubaBuffer[T]

	// pOut holds the intermediate polynomial in MulAssign, MulAdd or MulSub type operations.
	// This may take aditional O(N) loop, but the multiplication itself is a dominating factor,
	// so it doesn't matter.
	pOut Poly[T]
}

// karatsubaBuffer contains vuffer values for each karatsuba multiplication.
type karatsubaBuffer[T num.Integer] struct {
	// a0 = p0 + q0
	a0 Poly[T]
	// a1 = p1 + q1
	a1 Poly[T]
	// d0 = karatsuba(p0, q0)
	d0 Poly[T]
	// d1 = karatsuba(p1, q1)
	d1 Poly[T]
	// d2 = karatsuba(a0, a1)
	d2 Poly[T]
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
func newEvaluationBuffer[T num.Integer](N int) evaluaterBuffer[T] {
	// Allocate karatsuba buffers.
	// The full depth of the tree = log2(N / KaratsubaThreshold)
	depth := num.Log2(N / KaratsubaRecurseThreshold)
	// Number of nodes = 3^0 + 3^1 + ... + 3^depth = (3^(depth+1) - 1) / 2
	kBuff := make([]karatsubaBuffer[T], (num.Pow(3, depth+1)-1)/2)

	for i := 0; i < depth; i++ {
		for j := 0; j < num.Pow(3, i); j++ {
			treeIdx := (num.Pow(3, i)-1)/2 + j

			// In depth i, karatsuba inputs have size N / 2^i
			NN := N >> i
			kBuff[treeIdx] = karatsubaBuffer[T]{
				a0: New[T](NN / 2),
				a1: New[T](NN / 2),
				d0: New[T](NN),
				d1: New[T](NN),
				d2: New[T](NN),
			}
		}
	}

	return evaluaterBuffer[T]{
		karatsubaBuffer: kBuff,

		pOut: New[T](N),
	}
}

// ShallowCopy returns a shallow copy of this Evaluater.
// Returned Evaluater is safe for concurrent use.
func (e Evaluater[T]) ShallowCopy() Evaluater[T] {
	return Evaluater[T]{
		degree: e.degree,
	}
}

// Degree returns the degree of polynomial that the evaluater can handle.
func (e Evaluater[T]) Degree() int {
	return e.degree
}
