// Package poly implements polynomial and its operations.
package poly

import (
	"github.com/sp301415/tfhe/math/num"
	"github.com/sp301415/tfhe/math/vec"
)

// Poly represents the polynomial modulo X^N + 1. N should be power of two.
type Poly[T num.Integer] struct {
	Coeffs []T
}

// NewPoly creates a polynomial with degree N with empty coefficients.
// N should be power of two. Otherwise, it panics.
func New[T num.Integer](N int) Poly[T] {
	if !num.IsPowerOfTwo(N) {
		panic("degree not power of two")

	}
	return Poly[T]{Coeffs: make([]T, N)}
}

// From creates a new polynomial from given coefficient slice.
// The given slice is copied, and extended to degree N.
func From[T num.Integer](coeffs []T, N int) Poly[T] {
	p := New[T](N)
	vec.CopyAssign(coeffs, p.Coeffs)
	return p
}

// Copy returns a copy of the polynomial.
func (p Poly[T]) Copy() Poly[T] {
	return Poly[T]{Coeffs: vec.Copy(p.Coeffs)}
}

// CopyFrom copies p0 to p.
func (p *Poly[T]) CopyFrom(p0 Poly[T]) {
	vec.CopyAssign(p0.Coeffs, p.Coeffs)
}

// Degree returns the degree of the polynomial.
// This is equivalent with length of coefficients.
func (p Poly[T]) Degree() int {
	return len(p.Coeffs)
}

// Clear clears all the coefficients to zero.
func (p Poly[T]) Clear() {
	vec.Fill(p.Coeffs, 0)
}

// Equals checks if p0 is equal with p.
func (p Poly[T]) Equals(p0 Poly[T]) bool {
	return vec.Equals(p.Coeffs, p0.Coeffs)
}

// FourierPoly is a polynomial with Fourier Transform applied.
// Since we twist degree N polynomial in Z[x]/X^N+1 to
// degree N/2 polynomial in C[x]/X^N/2+1,
// we store N/2 coefficients, instead of N.
type FourierPoly struct {
	// Coeffs has length Degree / 2.
	Coeffs []complex128
}

// NewFourierPoly creates a fourier polynomial with degree N with empty coefficients.
// N should be power of two. Otherwise, it panics.
func NewFourierPoly(N int) FourierPoly {
	if !num.IsPowerOfTwo(N) {
		panic("degree not power of two")
	}
	return FourierPoly{Coeffs: make([]complex128, N/2)}
}

// Degree returns the degree of the polynomial.
func (p FourierPoly) Degree() int {
	return len(p.Coeffs) * 2
}

// Copy returns a copy of the polynomial.
func (p FourierPoly) Copy() FourierPoly {
	return FourierPoly{Coeffs: vec.Copy(p.Coeffs)}
}

// CopyFrom copies p0 to p.
func (p *FourierPoly) CopyFrom(p0 FourierPoly) {
	vec.CopyAssign(p0.Coeffs, p.Coeffs)
}

// Clear clears all the coefficients to zero.
func (p FourierPoly) Clear() {
	vec.Fill(p.Coeffs, 0)
}

// Equals checks if p0 is equal with p.
// Note that due to floating point errors,
// this function may return false even if p0 and p are equal.
func (p FourierPoly) Equals(p0 FourierPoly) bool {
	return vec.Equals(p.Coeffs, p0.Coeffs)
}
