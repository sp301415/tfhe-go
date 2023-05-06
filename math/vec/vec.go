package vec

import (
	"github.com/sp301415/tfhe/math/num"
	"golang.org/x/exp/constraints"
)

// checkLen2 checks if the length of v1 and v2 are the same, and panics if is not.
// If all vectors have the same length, it returns the length.
func checkLen2[T any](v1, v2 []T) int {
	if len(v1) != len(v2) {
		panic("length mismatch")
	}
	return len(v1)
}

// checkLen3 checks if the length of v1, v2 and v3 are the same, and panics if is not.
// If all vectors have the same length, it returns the length.
func checkLen3[T any](v1, v2, v3 []T) int {
	if len(v1) != len(v2) || len(v2) != len(v3) || len(v3) != len(v1) {
		panic("length mismatch")
	}
	return len(v1)
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
func Dot[T constraints.Integer](v1, v2 []T) T {
	checkLen2(v1, v2)

	var res T
	for i := range v1 {
		res += v1[i] * v2[i]
	}
	return res
}

// Add adds v0, v1 and returns the result.
func Add[T constraints.Integer](v0, v1 []T) []T {
	n := checkLen2(v0, v1)

	v := make([]T, n)
	AddInPlace(v0, v1, v)
	return v
}

// AddInPlace adds v0, v1 and writes it to vOut.
func AddInPlace[T constraints.Integer](v0, v1, vOut []T) {
	n := checkLen3(v0, v1, vOut)

	for i := 0; i < n; i++ {
		vOut[i] = v0[i] + v1[i]
	}
}

// AddAssign adds v0to vOut.
func AddAssign[T constraints.Integer](v0, vOut []T) {
	n := checkLen2(v0, vOut)

	for i := 0; i < n; i++ {
		vOut[i] += v0[i]
	}
}

// Sub subtracts v0, v1 and returns the result.
func Sub[T constraints.Integer](v0, v1 []T) []T {
	n := checkLen2(v0, v1)

	v := make([]T, n)
	SubInPlace(v0, v1, v)
	return v
}

// SubInPlace subtracts v0, v1 and writes it to pOut.
func SubInPlace[T constraints.Integer](v0, v1, vOut []T) {
	n := checkLen3(v0, v1, vOut)

	for i := 0; i < n; i++ {
		vOut[i] = v0[i] - v1[i]
	}
}

// SubAssign subtracts v0 from vOut.
func SubAssign[T constraints.Integer](v0, vOut []T) {
	n := checkLen2(v0, vOut)

	for i := 0; i < n; i++ {
		vOut[i] -= v0[i]
	}
}
