//go:build !(amd64 && !purego)

package vec

import "github.com/sp301415/tfhe-go/math/num"

// AddAssign computes vOut = v0 + v1.
func AddAssign[T num.Number](v0, v1, vOut []T) {
	for i := range vOut {
		vOut[i] = v0[i] + v1[i]
	}
}

// SubAssign computes vOut = v0 - v1.
func SubAssign[T num.Number](v0, v1, vOut []T) {
	for i := range vOut {
		vOut[i] = v0[i] - v1[i]
	}
}

// ScalarMulAssign computes vOut = c * v0.
func ScalarMulAssign[T num.Number](v0 []T, c T, vOut []T) {
	for i := range vOut {
		vOut[i] = c * v0[i]
	}
}

// ScalarMulAddAssign computes vOut += c * v0.
func ScalarMulAddAssign[T num.Number](v0 []T, c T, vOut []T) {
	for i := range vOut {
		vOut[i] += c * v0[i]
	}
}

// ScalarMulSubAssign computes vOut -= c * v0.
func ScalarMulSubAssign[T num.Number](v0 []T, c T, vOut []T) {
	for i := range vOut {
		vOut[i] -= c * v0[i]
	}
}

// ElementWiseMulAssign computes vOut = v0 * v1, where * is an elementwise multiplication.
func ElementWiseMulAssign[T num.Number](v0, v1, vOut []T) {
	for i := range vOut {
		vOut[i] = v0[i] * v1[i]
	}
}

// ElementWiseMulAddAssign computes vOut += v0 * v1, where * is an elementwise multiplication.
func ElementWiseMulAddAssign[T num.Number](v0, v1, vOut []T) {
	for i := range vOut {
		vOut[i] += v0[i] * v1[i]
	}
}

// ElementWiseMulSubAssign computes vOut -= v0 * v1, where * is an elementwise multiplication.
func ElementWiseMulSubAssign[T num.Number](v0, v1, vOut []T) {
	for i := range vOut {
		vOut[i] -= v0[i] * v1[i]
	}
}
