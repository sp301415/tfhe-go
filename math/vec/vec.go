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
	"golang.org/x/exp/constraints"
)

// Number represents Integer, Float, and Complex.
type Number interface {
	constraints.Integer | constraints.Float | constraints.Complex
}

// Rotate rotates the vector l times to the left.
// If l < 0, then it rotates the vector l times to the right.
// This uses the juggling algroithm, which takes O(N) time.
func Rotate[T any](s []T, l int) {
	if l < 0 {
		l = len(s) + l
	}
	l %= len(s)

	for i := 0; i < num.Gcd(len(s), l); i++ {
		tmp := s[i]
		j := i
		for {
			k := j + l
			if k >= len(s) {
				k -= len(s)
			}
			if k == i {
				break
			}
			s[j] = s[k]
			j = k
		}
		s[j] = tmp
	}
}

// Dot returns the dot product of two vectors.
func Dot[T Number](v1, v2 []T) T {
	var res T
	for i := range v1 {
		res += v1[i] * v2[i]
	}
	return res
}

// Add adds v0, v1 and returns the result.
func Add[T Number](v0, v1 []T) []T {
	v := make([]T, len(v0))
	AddInPlace(v0, v1, v)
	return v
}

// AddInPlace adds v0, v1 and writes it to vOut.
func AddInPlace[T Number](v0, v1, vOut []T) {
	for i := 0; i < len(vOut); i++ {
		vOut[i] = v0[i] + v1[i]
	}
}

// AddAssign adds v0to vOut.
func AddAssign[T Number](v0, vOut []T) {
	for i := 0; i < len(vOut); i++ {
		vOut[i] += v0[i]
	}
}

// Sub subtracts v0, v1 and returns the result.
func Sub[T Number](v0, v1 []T) []T {
	v := make([]T, len(v0))
	SubInPlace(v0, v1, v)
	return v
}

// SubInPlace subtracts v0, v1 and writes it to vOut.
func SubInPlace[T Number](v0, v1, vOut []T) {
	for i := 0; i < len(vOut); i++ {
		vOut[i] = v0[i] - v1[i]
	}
}

// SubAssign subtracts v0 from vOut.
func SubAssign[T Number](v0, vOut []T) {
	for i := 0; i < len(vOut); i++ {
		vOut[i] -= v0[i]
	}
}

// Neg negates v0 and returns the result.
func Neg[T Number](v0 []T) []T {
	v := make([]T, len(v0))
	NegInPlace(v0, v)
	return v
}

// NegInPlace negates v0 and writes it to vOut.
func NegInPlace[T Number](v0, vOut []T) {
	for i := 0; i < len(vOut); i++ {
		vOut[i] = -v0[i]
	}
}

// NegAssign negates v0.
func NegAssign[T Number](v0 []T) {
	for i := 0; i < len(v0); i++ {
		v0[i] = -v0[i]
	}
}

// ScalarMul multplies c to v0 and returns the result.
func ScalarMul[T Number](v0 []T, c T) []T {
	v := make([]T, len(v0))
	ScalarMulInPlace(v0, c, v)
	return v
}

// ScalarMulInPlace multplies c to v0 and writes it to vOut.
func ScalarMulInPlace[T Number](v0 []T, c T, vOut []T) {
	for i := 0; i < len(vOut); i++ {
		vOut[i] = c * v0[i]
	}
}

// ScalarMulAssign multplies c to vOut.
func ScalarMulAssign[T Number](c T, vOut []T) {
	ScalarMulInPlace(vOut, c, vOut)
}

// ScalarMulAddAssign multiplies c to v1 and adds to vOut.
func ScalarMulAddAssign[T Number](v0 []T, c T, vOut []T) {
	for i := 0; i < len(vOut); i++ {
		vOut[i] += c * v0[i]
	}
}

// ScalarMulSubAssign multiplies c to v0 and subtracts from vOut.
func ScalarMulSubAssign[T Number](v0 []T, c T, vOut []T) {
	for i := 0; i < len(vOut); i++ {
		vOut[i] -= c * v0[i]
	}
}

// ElementWiseMul multplies v0, v1 and returns the result.
func ElementWiseMul[T Number](v0 []T, v1 []T) []T {
	v := make([]T, len(v0))
	ElementWiseMulInPlace(v0, v1, v)
	return v
}

// ElementWiseMulInPlace multplies v0, v1 and writes it to vOut.
func ElementWiseMulInPlace[T Number](v0 []T, v1 []T, vOut []T) {
	for i := 0; i < len(vOut); i++ {
		vOut[i] = v0[i] * v1[i]
	}
}

// ElementWiseMulAssign multplies v to vOut.
func ElementWiseMulAssign[T Number](v []T, vOut []T) {
	for i := 0; i < len(vOut); i++ {
		vOut[i] *= v[i]
	}
}

// ElementWiseMulAddAssign multiplies v0, v1 and adds to vOut.
func ElementWiseMulAddAssign[T Number](v0 []T, v1 []T, vOut []T) {
	for i := 0; i < len(vOut); i++ {
		vOut[i] += v0[i] * v1[i]
	}
}

// ElementWiseMulSubAssign multiplies v0, v1 and subtracts from vOut.
func ElementWiseMulSubAssign[T Number](v0 []T, v1 []T, vOut []T) {
	for i := 0; i < len(vOut); i++ {
		vOut[i] -= v0[i] * v1[i]
	}
}
