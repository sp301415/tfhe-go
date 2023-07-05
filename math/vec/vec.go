// Package vec implements vector operations acting on slices.
//
// Operations usually take two forms: for example,
//   - Add(v0, v1) is equivalent to v := v0 + v1.
//   - AddInPlace(v0, v1, vOut) is equivalent to vOut = v0 + v1.
//     Sometimes, InPlace method only takes one argument, like BitReverse(v).
//     This means that input argument is altered.
//
// # Warning
//   - InPlace methods may not return correct results when output overlaps with inputs.
//     However, it is always correct when v0 == vOut or v1 == vOut.
//   - For performance reasons, functions in this package usually don't implement bound checks.
//     If length mismatch happens, usually the result is wrong.
package vec

import (
	"github.com/sp301415/tfhe/math/num"
)

// sliceEquals returns if two slice, v0 and v1, are really equal;
// This means that length, and pointer to the backing array is equal.
// (Capacity doesn't matter.)
func sliceEquals[T any](v0, v1 []T) bool {
	if len(v0) != len(v1) {
		return false
	}

	return len(v0) == 0 || &v0[0] == &v1[0]
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

// Cast casts and returns vector v of type []T1 to []T2.
func Cast[T1, T2 num.Real](v []T1) []T2 {
	vOut := make([]T2, len(v))
	CastInPlace(v, vOut)
	return vOut
}

// CastInPlace casts v of type []T1 to vOut of type []T2.
func CastInPlace[T1, T2 num.Real](v []T1, vOut []T2) {
	for i := range vOut {
		vOut[i] = T2(v[i])
	}
}

// Rotate rotates v l times to the right, and returns it.
// If l < 0, then it rotates the vector l times to the left.
// If Abs(l) > len(s), it may panic.
func Rotate[T any](v []T, l int) []T {
	vOut := make([]T, len(v))
	RotateInPlace(v, l, vOut)
	return vOut
}

// RotateInPlace rotates v l times to the right, and writes it to vOut.
// If l < 0, then it rotates the vector l times to the left.
func RotateInPlace[T any](v []T, l int, vOut []T) {
	if l < 0 {
		l = len(v) - ((-l) % len(v))
	} else {
		l %= len(v)
	}

	if sliceEquals(v, vOut) {
		ReverseInPlace(vOut, vOut)
		ReverseInPlace(vOut[:l], vOut[:l])
		ReverseInPlace(vOut[l:], vOut[l:])
	} else {
		CopyInPlace(v, vOut[l:])
		CopyInPlace(v[len(v)-l:], vOut[:l])
	}
}

// Reverse reverses v and returns it.
func Reverse[T any](v []T) []T {
	vOut := make([]T, len(v))
	ReverseInPlace(v, vOut)
	return vOut
}

// ReverseInPlace reverses v and writes it to vOut.
func ReverseInPlace[T any](v, vOut []T) {
	if sliceEquals(v, vOut) {
		for i, j := 0, len(v)-1; i < j; i, j = i+1, j-1 {
			vOut[i], vOut[j] = vOut[j], vOut[i]
		}
	} else {
		for i := range vOut {
			vOut[len(vOut)-i-1] = v[i]
		}
	}
}

// BitReverseInPlace reorders v into bit-reversal order.
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

// CopyInPlace copies v0 to v1.
func CopyInPlace[T any](v0, v1 []T) {
	copy(v1, v0)
}

// Dot returns the dot product of two vectors.
func Dot[T num.Number](v0, v1 []T) T {
	var res T
	for i := range v0 {
		res += v0[i] * v1[i]
	}
	return res
}

// Add adds v0, v1 and returns the result.
func Add[T num.Number](v0, v1 []T) []T {
	v := make([]T, len(v0))
	AddInPlace(v0, v1, v)
	return v
}

// AddInPlace adds v0, v1 and writes it to vOut.
func AddInPlace[T num.Number](v0, v1, vOut []T) {
	for i := range vOut {
		vOut[i] = v0[i] + v1[i]
	}
}

// Sub subtracts v0, v1 and returns the result.
func Sub[T num.Number](v0, v1 []T) []T {
	v := make([]T, len(v0))
	SubInPlace(v0, v1, v)
	return v
}

// SubInPlace subtracts v0, v1 and writes it to vOut.
func SubInPlace[T num.Number](v0, v1, vOut []T) {
	for i := range vOut {
		vOut[i] = v0[i] - v1[i]
	}
}

// Neg negates v0 and returns the result.
func Neg[T num.Number](v0 []T) []T {
	v := make([]T, len(v0))
	NegInPlace(v0, v)
	return v
}

// NegInPlace negates v0 and writes it to vOut.
func NegInPlace[T num.Number](v0, vOut []T) {
	for i := range vOut {
		vOut[i] = -v0[i]
	}
}

// ScalarMul multplies c to v0 and returns the result.
func ScalarMul[T num.Number](v0 []T, c T) []T {
	v := make([]T, len(v0))
	ScalarMulInPlace(v0, c, v)
	return v
}

// ScalarMulInPlace multplies c to v0 and writes it to vOut.
func ScalarMulInPlace[T num.Number](v0 []T, c T, vOut []T) {
	for i := range vOut {
		vOut[i] = c * v0[i]
	}
}

// ScalarMulAddInPlace multiplies c to v0 and adds to vOut.
func ScalarMulAddInPlace[T num.Number](v0 []T, c T, vOut []T) {
	for i := range vOut {
		vOut[i] += c * v0[i]
	}
}

// ScalarMulSubInPlace multiplies c to v0 and subtracts from vOut.
func ScalarMulSubInPlace[T num.Number](v0 []T, c T, vOut []T) {
	for i := range vOut {
		vOut[i] -= c * v0[i]
	}
}

// ElementWiseMul multplies v0, v1 and returns the result.
func ElementWiseMul[T num.Number](v0 []T, v1 []T) []T {
	v := make([]T, len(v0))
	ElementWiseMulInPlace(v0, v1, v)
	return v
}

// ElementWiseMulInPlace multplies v0, v1 and writes it to vOut.
func ElementWiseMulInPlace[T num.Number](v0 []T, v1 []T, vOut []T) {
	for i := range vOut {
		vOut[i] = v0[i] * v1[i]
	}
}

// ElementWiseMulAddInPlace multiplies v0, v1 and adds to vOut.
func ElementWiseMulAddInPlace[T num.Number](v0 []T, v1 []T, vOut []T) {
	for i := range vOut {
		vOut[i] += v0[i] * v1[i]
	}
}

// ElementWiseMulSubInPlace multiplies v0, v1 and subtracts from vOut.
func ElementWiseMulSubInPlace[T num.Number](v0 []T, v1 []T, vOut []T) {
	for i := range vOut {
		vOut[i] -= v0[i] * v1[i]
	}
}
