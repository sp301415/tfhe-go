// Package poly implements polynomial and its operations.
package poly

import (
	"math"

	"github.com/sp301415/tfhe-go/math/num"
	"github.com/sp301415/tfhe-go/math/vec"
)

// Poly is a polynomial over Z_Q[X]/(X^N + 1).
type Poly[T num.Integer] struct {
	Coeffs []T
}

// NewPoly creates a polynomial with rank N with empty coefficients.
//
// Panics when N is not a power of two, or when N is smaller than [MinRank].
func NewPoly[T num.Integer](N int) Poly[T] {
	switch {
	case !num.IsPowerOfTwo(N):
		panic("NewPoly: rank not power of two")
	case N < MinRank:
		panic("NewPoly: rank smaller than MinRank")
	}

	return Poly[T]{Coeffs: make([]T, N)}
}

// From creates a new polynomial from given coefficient slice.
// The given slice is copied, and extended to rank N.
func From[T num.Integer](coeffs []T, N int) Poly[T] {
	p := NewPoly[T](N)
	copy(p.Coeffs, coeffs)
	return p
}

// Copy returns a copy of the polynomial.
func (p Poly[T]) Copy() Poly[T] {
	return Poly[T]{Coeffs: vec.Copy(p.Coeffs)}
}

// CopyFrom copies p0 to p.
func (p *Poly[T]) CopyFrom(pIn Poly[T]) {
	copy(p.Coeffs, pIn.Coeffs)
}

// Rank returns the rank of the polynomial.
// This is equivalent with length of coefficients.
func (p Poly[T]) Rank() int {
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

// FFTPoly is a fourier transformed polynomial over C[X]/(X^N/2 + 1).
// This corresponds to a polynomial over Z_Q[X]/(X^N + 1).
type FFTPoly struct {
	// Coeffs is represented as float-4 complex vector
	// for efficient computation.
	//
	// Namely,
	//
	//	[(r0, i0), (r1, i1), (r2, i2), (r3, i3), ...]
	//
	// is represented as
	//
	//	[(r0, r1, r2, r3), (i0, i1, i2, i3), ...]
	//
	Coeffs []float64
}

// NewFFTPoly creates a fourier polynomial with rank N/2 with empty coefficients.
//
// Panics when N is not a power of two, or when N is smaller than [MinRank].
func NewFFTPoly(N int) FFTPoly {
	switch {
	case !num.IsPowerOfTwo(N):
		panic("NewFFTPoly: rank not power of two")
	case N < MinRank:
		panic("NewFFTPoly: rank smaller than MinRank")
	}

	return FFTPoly{Coeffs: make([]float64, N)}
}

// Rank returns the (doubled) rank of the polynomial.
func (p FFTPoly) Rank() int {
	return len(p.Coeffs)
}

// Copy returns a copy of the polynomial.
func (p FFTPoly) Copy() FFTPoly {
	return FFTPoly{Coeffs: vec.Copy(p.Coeffs)}
}

// CopyFrom copies p0 to p.
func (p *FFTPoly) CopyFrom(pIn FFTPoly) {
	copy(p.Coeffs, pIn.Coeffs)
}

// Clear clears all the coefficients to zero.
func (p FFTPoly) Clear() {
	vec.Fill(p.Coeffs, 0)
}

// Equals checks if p0 is equal with p.
// Note that due to floating point errors,
// this function may return false even if p0 and p are equal.
func (p FFTPoly) Equals(p0 FFTPoly) bool {
	return vec.Equals(p.Coeffs, p0.Coeffs)
}

// Approx checks if p0 is approximately equal with p,
// with a difference smaller than eps.
func (p FFTPoly) Approx(p0 FFTPoly, eps float64) bool {
	for i := range p.Coeffs {
		if math.Abs(p.Coeffs[i]-p0.Coeffs[i]) > eps {
			return false
		}
	}
	return true
}
