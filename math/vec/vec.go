package vec

import (
	"github.com/sp301415/tfhe/math/num"
	"golang.org/x/exp/constraints"
)

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
	var res T
	for i := range v1 {
		res += v1[i] * v2[i]
	}
	return res
}

// Add adds v0, v1 and returns the result.
func Add[T constraints.Integer](v0, v1 []T) []T {
	v := make([]T, len(v0))
	AddInPlace(v0, v1, v)
	return v
}

// AddInPlace adds v0, v1 and writes it to vOut.
func AddInPlace[T constraints.Integer](v0, v1, vOut []T) {
	for i := 0; i < len(vOut); i++ {
		vOut[i] = v0[i] + v1[i]
	}
}

// AddAssign adds v0to vOut.
func AddAssign[T constraints.Integer](v0, vOut []T) {
	for i := 0; i < len(vOut); i++ {
		vOut[i] += v0[i]
	}
}

// Sub subtracts v0, v1 and returns the result.
func Sub[T constraints.Integer](v0, v1 []T) []T {
	v := make([]T, len(v0))
	SubInPlace(v0, v1, v)
	return v
}

// SubInPlace subtracts v0, v1 and writes it to pOut.
func SubInPlace[T constraints.Integer](v0, v1, vOut []T) {
	for i := 0; i < len(vOut); i++ {
		vOut[i] = v0[i] - v1[i]
	}
}

// SubAssign subtracts v0 from vOut.
func SubAssign[T constraints.Integer](v0, vOut []T) {
	for i := 0; i < len(vOut); i++ {
		vOut[i] -= v0[i]
	}
}
