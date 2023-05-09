// Package vec implements vector operations action on slices.
//
// Operations usually take three forms: for example,
//   - Add(v0, v1) is equivalent to v := v0 + v1
//   - AddInPlace(v0, v1, vOut) is equivalent to vOut = v0 + v1
//   - AddAssign(v0, vOut) is equivalent to vOut += v0
//
// For performance reasons, functions in this package usually don't implement bound checks,
// so be careful.
package vec

import (
	"github.com/sp301415/tfhe/math/num"
)

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

	copy(vOut[l:], v)
	copy(vOut[:l], v[len(v)-l:])
}

// RotateAssign rotates v l times to the right.
// If l < 0, then it rotates the vector l times to the left.
func RotateAssign[T any](v []T, l int) {
	if l < 0 {
		l = len(v) - ((-l) % len(v))
	} else {
		l %= len(v)
	}

	ReverseAssign(v)
	ReverseAssign(v[:l])
	ReverseAssign(v[l:])
}

// Reverse reverses v and returns it.
func Reverse[T any](v []T) []T {
	vOut := make([]T, len(v))
	ReverseInPlace(v, vOut)
	return vOut
}

// ReverseInPlace reverses v and writes it to vOut.
func ReverseInPlace[T any](v, vOut []T) {
	for i := 0; i < len(vOut); i++ {
		vOut[len(vOut)-i-1] = v[i]
	}
}

// ReverseAssign reverses v.
func ReverseAssign[T any](v []T) {
	for i, j := 0, len(v)-1; i < j; i, j = i+1, j-1 {
		v[i], v[j] = v[j], v[i]
	}
}

// Chunk reslices the vector to subslices each of size chunkSize.
func Chunk[T any](s []T, chunkSize int) [][]T {
	chunkCount := num.RoundRatio(len(s), chunkSize)
	result := make([][]T, chunkCount)

	for i := 0; i < chunkCount-1; i++ {
		result[i] = s[i*chunkSize : (i+1)*chunkSize]
	}
	result[chunkCount-1] = s[(chunkCount-1)*chunkSize:]

	return result
}

// Dot returns the dot product of two vectors.
func Dot[T num.Number](v1, v2 []T) T {
	var res T
	for i := range v1 {
		res += v1[i] * v2[i]
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
	for i := 0; i < len(vOut); i++ {
		vOut[i] = v0[i] + v1[i]
	}
}

// AddAssign adds v0to vOut.
func AddAssign[T num.Number](v0, vOut []T) {
	for i := 0; i < len(vOut); i++ {
		vOut[i] += v0[i]
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
	for i := 0; i < len(vOut); i++ {
		vOut[i] = v0[i] - v1[i]
	}
}

// SubAssign subtracts v0 from vOut.
func SubAssign[T num.Number](v0, vOut []T) {
	for i := 0; i < len(vOut); i++ {
		vOut[i] -= v0[i]
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
	for i := 0; i < len(vOut); i++ {
		vOut[i] = -v0[i]
	}
}

// NegAssign negates v0.
func NegAssign[T num.Number](v0 []T) {
	for i := 0; i < len(v0); i++ {
		v0[i] = -v0[i]
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
	for i := 0; i < len(vOut); i++ {
		vOut[i] = c * v0[i]
	}
}

// ScalarMulAssign multplies c to vOut.
func ScalarMulAssign[T num.Number](c T, vOut []T) {
	ScalarMulInPlace(vOut, c, vOut)
}

// ScalarMulAddAssign multiplies c to v1 and adds to vOut.
func ScalarMulAddAssign[T num.Number](v0 []T, c T, vOut []T) {
	for i := 0; i < len(vOut); i++ {
		vOut[i] += c * v0[i]
	}
}

// ScalarMulSubAssign multiplies c to v0 and subtracts from vOut.
func ScalarMulSubAssign[T num.Number](v0 []T, c T, vOut []T) {
	for i := 0; i < len(vOut); i++ {
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
	for i := 0; i < len(vOut); i++ {
		vOut[i] = v0[i] * v1[i]
	}
}

// ElementWiseMulAssign multplies v to vOut.
func ElementWiseMulAssign[T num.Number](v []T, vOut []T) {
	for i := 0; i < len(vOut); i++ {
		vOut[i] *= v[i]
	}
}

// ElementWiseMulAddAssign multiplies v0, v1 and adds to vOut.
func ElementWiseMulAddAssign[T num.Number](v0 []T, v1 []T, vOut []T) {
	for i := 0; i < len(vOut); i++ {
		vOut[i] += v0[i] * v1[i]
	}
}

// ElementWiseMulSubAssign multiplies v0, v1 and subtracts from vOut.
func ElementWiseMulSubAssign[T num.Number](v0 []T, v1 []T, vOut []T) {
	for i := 0; i < len(vOut); i++ {
		vOut[i] -= v0[i] * v1[i]
	}
}
