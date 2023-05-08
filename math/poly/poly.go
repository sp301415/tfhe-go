// Package poly implements polynomial and its operations.
//
// Most polynomial operations are done using Evaluater. Operations usually take three forms: for example,
//   - Add(p0, p1) is equivalent to var p = p0 + p1
//   - AddInPlace(p0, p1, pOut) is equivalent to pOut = p0 + p1
//   - AddAssign(p0, pOut) is equivalent to pOut += p0
//
// For performance reasons, functions in this package usually don't implement bound checks,
// so be careful.
package poly

import (
	"github.com/sp301415/tfhe/math/num"
	"golang.org/x/exp/constraints"
	"golang.org/x/exp/slices"
)

// Poly represents the polynomial modulo X^N + 1. N should be power of two.
type Poly[T constraints.Integer] struct {
	Coeffs []T
}

// NewPoly creates a polynomial with degree N with empty coefficients.
// N should be power of two. Otherwise, it panics.
func New[T constraints.Integer](N int) Poly[T] {
	if !num.IsPowerOfTwo(N) {
		panic("degree not power of two")

	}
	return Poly[T]{Coeffs: make([]T, N)}
}

// From creates a new polynomial from given coefficient slice.
// This function has potential side effects, as it does not copy the slice.
func From[T constraints.Integer](coeffs []T) Poly[T] {
	if !num.IsPowerOfTwo(len(coeffs)) {
		panic("degree not power of two")
	}
	return Poly[T]{Coeffs: coeffs}
}

// Copy returns a copy of the polynomial.
func (p Poly[T]) Copy() Poly[T] {
	return Poly[T]{Coeffs: slices.Clone(p.Coeffs)}
}

// CopyFrom copies p0 to p.
func (p Poly[T]) CopyFrom(p0 Poly[T]) {
	copy(p.Coeffs, p0.Coeffs)
}

// Degree returns the degree of the polynomial.
// This is equivalent with length of coefficients.
func (p Poly[T]) Degree() int {
	return len(p.Coeffs)
}

// Clear clears all the coefficients to zero.
func (p Poly[T]) Clear() {
	for i := range p.Coeffs {
		p.Coeffs[i] = 0
	}
}
