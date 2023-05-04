package vec

import "golang.org/x/exp/constraints"

// checkLen2 checks if the length of v1 and v2 are the same, and panics if is not.
func checkLen2[T any](v1, v2 []T) {
	if len(v1) != len(v2) {
		panic("length mismatch")
	}
}

// checkLen3 checks if the length of v1, v2 and v3 are the same, and panics if is not.
func checkLen3[T any](v1, v2, v3 []T) {
	if len(v1) != len(v2) || len(v2) != len(v3) || len(v3) != len(v1) {
		panic("length mismatch")
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
