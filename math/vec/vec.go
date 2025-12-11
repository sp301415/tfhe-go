// Package vec implements vector operations acting on slices.
//
// Operations usually take two forms: for example,
//   - Op(v0, v1) operates on v0, v1, allocates a new vector to store the result and returns it.
//   - OpTo(vOut, v0, v1) operates on v0, v1 and writes the result to pre-allocated vOut without returning.
//
// Note that in most cases, v0, v1, and vOut can overlap.
// However, for operations that cannot, InPlace methods are implemented separately.
package vec

import (
	"github.com/sp301415/tfhe-go/math/num"
)

// checkConsistent checks if all vectors have the same length,
// and panics if not.
func checkConsistent(xs ...int) {
	if len(xs) == 0 {
		return
	}

	for i := 1; i < len(xs); i++ {
		if xs[i] != xs[0] {
			panic("inconsistent inputs")
		}
	}
}

// Equals returns if two vectors are equal.
func Equals[T comparable](v0, v1 []T) bool {
	if len(v0) != len(v1) {
		return false
	}

	for i := range v0 {
		if v0[i] != v1[i] {
			return false
		}
	}
	return true
}

// Fill fills vector with x.
func Fill[T any](v []T, x T) {
	for i := range v {
		v[i] = x
	}
}

// Cast casts vector v of type []T1 to []T2.
func Cast[TOut, TIn num.Real](v []TIn) []TOut {
	vOut := make([]TOut, len(v))
	CastTo(vOut, v)
	return vOut
}

// CastTo casts v of type []TIn to vOut of type []TOut.
func CastTo[TOut, TIn num.Real](vOut []TOut, v []TIn) {
	checkConsistent(len(vOut), len(v))

	for i := range vOut {
		vOut[i] = TOut(v[i])
	}
}

// Rotate rotates v l times to the right.
// If l < 0, then it rotates the vector l times to the left.
// If Abs(l) > len(s), it may panic.
func Rotate[T any](v []T, l int) []T {
	vOut := make([]T, len(v))
	RotateTo(vOut, v, l)
	return vOut
}

// RotateTo rotates v l times to the right and writes it to vOut.
// If l < 0, then it rotates the vector l times to the left.
//
// v and vOut should not overlap. For rotating a slice inplace,
// use [vec.RotateInPlace].
func RotateTo[T any](vOut, v []T, l int) {
	checkConsistent(len(vOut), len(v))

	if l < 0 {
		l = len(v) - ((-l) % len(v))
	} else {
		l %= len(v)
	}

	copy(vOut[l:], v)
	copy(vOut[:l], v[len(v)-l:])
}

// RotateInPlace rotates v l times to the right in-place.
// If l < 0, then it rotates the vector l times to the left.
func RotateInPlace[T any](v []T, l int) {
	if l < 0 {
		l = len(v) - ((-l) % len(v))
	} else {
		l %= len(v)
	}

	ReverseInPlace(v)
	ReverseInPlace(v[:l])
	ReverseInPlace(v[l:])
}

// Reverse reverses v.
func Reverse[T any](v []T) []T {
	vOut := make([]T, len(v))
	ReverseTo(vOut, v)
	return vOut
}

// ReverseTo reverse v and writes it to vOut.
//
// v and vOut should not overlap. For reversing a slice inplace,
// use [vec.ReverseInPlace].
func ReverseTo[T any](vOut, v []T) {
	checkConsistent(len(vOut), len(v))

	for i := range vOut {
		vOut[len(vOut)-i-1] = v[i]
	}
}

// ReverseInPlace reverses v in-place.
func ReverseInPlace[T any](v []T) {
	for i, j := 0, len(v)-1; i < j; i, j = i+1, j-1 {
		v[i], v[j] = v[j], v[i]
	}
}

// BitReverseInPlace reorders v into bit-reversal order in-place.
func BitReverseInPlace[T any](v []T) {
	var bit, j int
	for i := 1; i < len(v); i++ {
		bit = len(v) >> 1
		for j >= bit {
			j -= bit
			bit >>= 1
		}
		j += bit
		if i < j {
			v[i], v[j] = v[j], v[i]
		}
	}
}

// Copy returns a copy of v.
func Copy[T any](v []T) []T {
	if v == nil {
		return nil
	}
	return append(make([]T, 0, len(v)), v...)
}

// Dot returns the dot product of two vectors.
func Dot[T num.Number](v0, v1 []T) T {
	checkConsistent(len(v0), len(v1))

	var res T
	for i := range v0 {
		res += v0[i] * v1[i]
	}
	return res
}

// Add returns v0 + v1.
func Add[T num.Number](v0, v1 []T) []T {
	vOut := make([]T, len(v0))
	AddTo(vOut, v0, v1)
	return vOut
}

// Sub returns v0 - v1.
func Sub[T num.Number](v0, v1 []T) []T {
	vOut := make([]T, len(v0))
	SubTo(vOut, v0, v1)
	return vOut
}

// Neg returns -v.
func Neg[T num.Number](v []T) []T {
	vOut := make([]T, len(v))
	NegTo(vOut, v)
	return vOut
}

// NegTo computes vOut = -v.
func NegTo[T num.Number](vOut, v []T) {
	checkConsistent(len(vOut), len(v))

	for i := range vOut {
		vOut[i] = -v[i]
	}
}

// ScalarMul returns c * v0.
func ScalarMul[T num.Number](v0 []T, c T) []T {
	vOut := make([]T, len(v0))
	ScalarMulTo(vOut, v0, c)
	return vOut
}

// Mul returns v0 * v1, where * is an elementwise multiplication.
func Mul[T num.Number](v0, v1 []T) []T {
	vOut := make([]T, len(v0))
	MulTo(vOut, v0, v1)
	return vOut
}

// CmplxToFloat4 converts a complex128 vector to
// float-4 representation used in fourier polynomials.
//
// Namely, it converts
//
//	[(r0, i0), (r1, i1), (r2, i2), (r3, i3), ...]
//
// to
//
//	[(r0, r1, r2, r3), (i0, i1, i2, i3), ...]
//
// The length of the input vector should be multiple of 4.
func CmplxToFloat4(v []complex128) []float64 {
	vOut := make([]float64, 2*len(v))
	CmplxToFloat4To(vOut, v)
	return vOut
}

// CmplxToFloat4To converts a complex128 vector to
// float-4 representation used in fourier polynomials and writes it to vOut.
//
// Namely, it converts
//
//	[(r0, i0), (r1, i1), (r2, i2), (r3, i3), ...]
//
// to
//
//	[(r0, r1, r2, r3), (i0, i1, i2, i3), ...]
//
// The length of the input vector should be multiple of 4,
// and the length of vOut should be 2 times of the length of v.
func CmplxToFloat4To(vOut []float64, v []complex128) {
	switch {
	case len(v)%4 != 0:
		panic("input length must be multiple of 4")
	case len(vOut) != 2*len(v):
		panic("output length must be twice of input length")
	}

	for i, j := 0, 0; i < len(v); i, j = i+4, j+8 {
		vOut[j+0] = real(v[i+0])
		vOut[j+1] = real(v[i+1])
		vOut[j+2] = real(v[i+2])
		vOut[j+3] = real(v[i+3])

		vOut[j+4] = imag(v[i+0])
		vOut[j+5] = imag(v[i+1])
		vOut[j+6] = imag(v[i+2])
		vOut[j+7] = imag(v[i+3])
	}
}

// Float4ToCmplx converts a float-4 complex vector to
// naturally represented complex128 vector.
//
// Namely, it converts
//
//	[(r0, r1, r2, r3), (i0, i1, i2, i3), ...]
//
// to
//
//	[(r0, i0), (r1, i1), (r2, i2), (r3, i3), ...]
//
// The length of the input vector should be multiple of 8.
func Float4ToCmplx(v []float64) []complex128 {
	vOut := make([]complex128, len(v)/2)
	Float4ToCmplxTo(vOut, v)
	return vOut
}

// Float4ToCmplxTo converts a float-4 complex vector to
// naturally represented complex128 vector and writes it to vOut.
//
// Namely, it converts
//
//	[(r0, r1, r2, r3), (i0, i1, i2, i3), ...]
//
// to
//
//	[(r0, i0), (r1, i1), (r2, i2), (r3, i3), ...]
//
// The length of the input vector should be multiple of 8,
// and the length of vOut should be half of the length of v.
func Float4ToCmplxTo(vOut []complex128, v []float64) {
	switch {
	case len(v)%8 != 0:
		panic("input length must be multiple of 8")
	case len(vOut)*2 != len(v):
		panic("output length must be half of input length")
	}

	for i, j := 0, 0; i < len(v); i, j = i+8, j+4 {
		vOut[j+0] = complex(v[i+0], v[i+4])
		vOut[j+1] = complex(v[i+1], v[i+5])
		vOut[j+2] = complex(v[i+2], v[i+6])
		vOut[j+3] = complex(v[i+3], v[i+7])
	}
}
