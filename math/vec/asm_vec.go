//go:build !(amd64 && !purego)

package vec

import (
	"unsafe"

	"github.com/sp301415/tfhe-go/math/num"
)

// AddTo computes vOut = v0 + v1.
func AddTo[T num.Number](vOut, v0, v1 []T) {
	M := (len(vOut) >> 3) << 3

	for i := 0; i < M; i += 8 {
		wOut := (*[8]T)(unsafe.Pointer(&vOut[i]))
		w0 := (*[8]T)(unsafe.Pointer(&v0[i]))
		w1 := (*[8]T)(unsafe.Pointer(&v1[i]))

		wOut[0] = w0[0] + w1[0]
		wOut[1] = w0[1] + w1[1]
		wOut[2] = w0[2] + w1[2]
		wOut[3] = w0[3] + w1[3]

		wOut[4] = w0[4] + w1[4]
		wOut[5] = w0[5] + w1[5]
		wOut[6] = w0[6] + w1[6]
		wOut[7] = w0[7] + w1[7]
	}

	for i := M; i < len(vOut); i++ {
		vOut[i] = v0[i] + v1[i]
	}
}

// SubTo computes vOut = v0 - v1.
func SubTo[T num.Number](vOut, v0, v1 []T) {
	M := (len(vOut) >> 3) << 3

	for i := 0; i < M; i += 8 {
		wOut := (*[8]T)(unsafe.Pointer(&vOut[i]))
		w0 := (*[8]T)(unsafe.Pointer(&v0[i]))
		w1 := (*[8]T)(unsafe.Pointer(&v1[i]))

		wOut[0] = w0[0] - w1[0]
		wOut[1] = w0[1] - w1[1]
		wOut[2] = w0[2] - w1[2]
		wOut[3] = w0[3] - w1[3]

		wOut[4] = w0[4] - w1[4]
		wOut[5] = w0[5] - w1[5]
		wOut[6] = w0[6] - w1[6]
		wOut[7] = w0[7] - w1[7]
	}

	for i := M; i < len(vOut); i++ {
		vOut[i] = v0[i] - v1[i]
	}
}

// ScalarMulTo computes vOut = c * v.
func ScalarMulTo[T num.Number](vOut, v []T, c T) {
	M := (len(vOut) >> 3) << 3

	for i := 0; i < M; i += 8 {
		wOut := (*[8]T)(unsafe.Pointer(&vOut[i]))
		w := (*[8]T)(unsafe.Pointer(&v[i]))

		wOut[0] = c * w[0]
		wOut[1] = c * w[1]
		wOut[2] = c * w[2]
		wOut[3] = c * w[3]

		wOut[4] = c * w[4]
		wOut[5] = c * w[5]
		wOut[6] = c * w[6]
		wOut[7] = c * w[7]
	}

	for i := M; i < len(vOut); i++ {
		vOut[i] = c * v[i]
	}
}

// ScalarMulAddTo computes vOut += c * v.
func ScalarMulAddTo[T num.Number](vOut, v []T, c T) {
	M := (len(vOut) >> 3) << 3

	for i := 0; i < M; i += 8 {
		wOut := (*[8]T)(unsafe.Pointer(&vOut[i]))
		w := (*[8]T)(unsafe.Pointer(&v[i]))

		wOut[0] += c * w[0]
		wOut[1] += c * w[1]
		wOut[2] += c * w[2]
		wOut[3] += c * w[3]

		wOut[4] += c * w[4]
		wOut[5] += c * w[5]
		wOut[6] += c * w[6]
		wOut[7] += c * w[7]
	}

	for i := M; i < len(vOut); i++ {
		vOut[i] += c * v[i]
	}
}

// ScalarMulSubTo computes vOut -= c * v0.
func ScalarMulSubTo[T num.Number](vOut, v []T, c T) {
	M := (len(vOut) >> 3) << 3

	for i := 0; i < M; i += 8 {
		wOut := (*[8]T)(unsafe.Pointer(&vOut[i]))
		w := (*[8]T)(unsafe.Pointer(&v[i]))

		wOut[0] -= c * w[0]
		wOut[1] -= c * w[1]
		wOut[2] -= c * w[2]
		wOut[3] -= c * w[3]

		wOut[4] -= c * w[4]
		wOut[5] -= c * w[5]
		wOut[6] -= c * w[6]
		wOut[7] -= c * w[7]
	}

	for i := M; i < len(vOut); i++ {
		vOut[i] -= c * v[i]
	}
}

// MulTo computes vOut = v0 * v1, where * is an elementwise multiplication.
func MulTo[T num.Number](vOut, v0, v1 []T) {
	M := (len(vOut) >> 3) << 3

	for i := 0; i < M; i += 8 {
		wOut := (*[8]T)(unsafe.Pointer(&vOut[i]))
		w0 := (*[8]T)(unsafe.Pointer(&v0[i]))
		w1 := (*[8]T)(unsafe.Pointer(&v1[i]))

		wOut[0] = w0[0] * w1[0]
		wOut[1] = w0[1] * w1[1]
		wOut[2] = w0[2] * w1[2]
		wOut[3] = w0[3] * w1[3]

		wOut[4] = w0[4] * w1[4]
		wOut[5] = w0[5] * w1[5]
		wOut[6] = w0[6] * w1[6]
		wOut[7] = w0[7] * w1[7]
	}

	for i := M; i < len(vOut); i++ {
		vOut[i] = v0[i] * v1[i]
	}
}

// MulAddTo computes vOut += v0 * v1, where * is an elementwise multiplication.
func MulAddTo[T num.Number](vOut, v0, v1 []T) {
	M := (len(vOut) >> 3) << 3

	for i := 0; i < M; i += 8 {
		wOut := (*[8]T)(unsafe.Pointer(&vOut[i]))
		w0 := (*[8]T)(unsafe.Pointer(&v0[i]))
		w1 := (*[8]T)(unsafe.Pointer(&v1[i]))

		wOut[0] += w0[0] * w1[0]
		wOut[1] += w0[1] * w1[1]
		wOut[2] += w0[2] * w1[2]
		wOut[3] += w0[3] * w1[3]

		wOut[4] += w0[4] * w1[4]
		wOut[5] += w0[5] * w1[5]
		wOut[6] += w0[6] * w1[6]
		wOut[7] += w0[7] * w1[7]
	}

	for i := M; i < len(vOut); i++ {
		vOut[i] += v0[i] * v1[i]
	}
}

// MulSubTo computes vOut -= v0 * v1, where * is an elementwise multiplication.
func MulSubTo[T num.Number](vOut, v0, v1 []T) {
	M := (len(vOut) >> 3) << 3

	for i := 0; i < M; i += 8 {
		wOut := (*[8]T)(unsafe.Pointer(&vOut[i]))
		w0 := (*[8]T)(unsafe.Pointer(&v0[i]))
		w1 := (*[8]T)(unsafe.Pointer(&v1[i]))

		wOut[0] -= w0[0] * w1[0]
		wOut[1] -= w0[1] * w1[1]
		wOut[2] -= w0[2] * w1[2]
		wOut[3] -= w0[3] * w1[3]

		wOut[4] -= w0[4] * w1[4]
		wOut[5] -= w0[5] * w1[5]
		wOut[6] -= w0[6] * w1[6]
		wOut[7] -= w0[7] * w1[7]
	}

	for i := M; i < len(vOut); i++ {
		vOut[i] -= v0[i] * v1[i]
	}
}
