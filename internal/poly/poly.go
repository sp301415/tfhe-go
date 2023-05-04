package poly

import (
	"github.com/sp301415/tfhe/internal/num"
	"golang.org/x/exp/constraints"
	"golang.org/x/exp/slices"
)

// Poly represents the polynomial modulo X^N + 1. N should be power of two.
//
// Operations on polynomial has three types. For example, for addition,
//
//   - poly.Add(a, b Poly) Poly returns the new polynomial p = a + b.
//   - p.Add(a, b) assigns a + b to p. No memory allocation is performed.
//   - p.AddAssign(a) assigns p + a to p. No memory allocation is performed.
type Poly[T constraints.Integer] struct {
	Coeffs []T
}

// NewPoly creates a polynomial with degree N with empty coefficients.
// N should be power of two.
func New[T constraints.Integer](N int) Poly[T] {
	if !num.IsPowerOfTwo(N) {
		panic("degree should be power of two")

	}
	return Poly[T]{Coeffs: make([]T, N)}
}

// From copies the slice, and creates a polynomial from it.
// Length of the slice should be power of two.
func From[T constraints.Integer](coeffs []T) Poly[T] {
	if !num.IsPowerOfTwo(len(coeffs)) {
		panic("degree should be power of two")
	}
	return Poly[T]{Coeffs: slices.Clone(coeffs)}
}

// Copy returns a copy of the polynomial.
func (p Poly[T]) Copy() Poly[T] {
	return Poly[T]{Coeffs: slices.Clone(p.Coeffs)}
}

// Degree returns the degree of the polynomial.
// This is equivalent with length of coefficients.
func (p Poly[T]) Degree() int {
	return len(p.Coeffs)
}
