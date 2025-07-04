//go:build amd64 && !purego

package vec

import (
	"unsafe"

	"github.com/sp301415/tfhe-go/math/num"
	"golang.org/x/sys/cpu"
)

// AddAssign computes vOut = v0 + v1.
func AddAssign[T num.Number](v0, v1, vOut []T) {
	if cpu.X86.HasAVX2 && cpu.X86.HasFMA {
		var z T
		switch any(z).(type) {
		case uint32:
			addAssignUint32AVX2(
				*(*[]uint32)(unsafe.Pointer(&v0)),
				*(*[]uint32)(unsafe.Pointer(&v1)),
				*(*[]uint32)(unsafe.Pointer(&vOut)),
			)
			return

		case uint64:
			addAssignUint64AVX2(
				*(*[]uint64)(unsafe.Pointer(&v0)),
				*(*[]uint64)(unsafe.Pointer(&v1)),
				*(*[]uint64)(unsafe.Pointer(&vOut)),
			)
			return
		}
	}

	M := (len(vOut) >> 3) << 3

	for i := 0; i < M; i += 8 {
		w0 := (*[8]T)(unsafe.Pointer(&v0[i]))
		w1 := (*[8]T)(unsafe.Pointer(&v1[i]))
		wOut := (*[8]T)(unsafe.Pointer(&vOut[i]))

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

// SubAssign computes vOut = v0 - v1.
func SubAssign[T num.Number](v0, v1, vOut []T) {
	if cpu.X86.HasAVX2 && cpu.X86.HasFMA {
		var z T
		switch any(z).(type) {
		case uint32:
			subAssignUint32AVX2(
				*(*[]uint32)(unsafe.Pointer(&v0)),
				*(*[]uint32)(unsafe.Pointer(&v1)),
				*(*[]uint32)(unsafe.Pointer(&vOut)),
			)
			return

		case uint64:
			subAssignUint64AVX2(
				*(*[]uint64)(unsafe.Pointer(&v0)),
				*(*[]uint64)(unsafe.Pointer(&v1)),
				*(*[]uint64)(unsafe.Pointer(&vOut)),
			)
			return
		}
	}

	M := (len(vOut) >> 3) << 3

	for i := 0; i < M; i += 8 {
		w0 := (*[8]T)(unsafe.Pointer(&v0[i]))
		w1 := (*[8]T)(unsafe.Pointer(&v1[i]))
		wOut := (*[8]T)(unsafe.Pointer(&vOut[i]))

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

// ScalarMulAssign computes vOut = c * v0.
func ScalarMulAssign[T num.Number](v0 []T, c T, vOut []T) {
	if cpu.X86.HasAVX2 && cpu.X86.HasFMA {
		var z T
		switch any(z).(type) {
		case uint32:
			scalarMulAssignUint32AVX2(
				*(*[]uint32)(unsafe.Pointer(&v0)),
				*(*uint32)(unsafe.Pointer(&c)),
				*(*[]uint32)(unsafe.Pointer(&vOut)),
			)
			return

		case uint64:
			scalarMulAssignUint64AVX2(
				*(*[]uint64)(unsafe.Pointer(&v0)),
				*(*uint64)(unsafe.Pointer(&c)),
				*(*[]uint64)(unsafe.Pointer(&vOut)),
			)
			return
		}
	}

	M := (len(vOut) >> 3) << 3

	for i := 0; i < M; i += 8 {
		w0 := (*[8]T)(unsafe.Pointer(&v0[i]))
		wOut := (*[8]T)(unsafe.Pointer(&vOut[i]))

		wOut[0] = c * w0[0]
		wOut[1] = c * w0[1]
		wOut[2] = c * w0[2]
		wOut[3] = c * w0[3]

		wOut[4] = c * w0[4]
		wOut[5] = c * w0[5]
		wOut[6] = c * w0[6]
		wOut[7] = c * w0[7]
	}

	for i := M; i < len(vOut); i++ {
		vOut[i] = c * v0[i]
	}
}

// ScalarMulAddAssign computes vOut += c * v0.
func ScalarMulAddAssign[T num.Number](v0 []T, c T, vOut []T) {
	if cpu.X86.HasAVX2 && cpu.X86.HasFMA {
		var z T
		switch any(z).(type) {
		case uint32:
			scalarMulAddAssignUint32AVX2(
				*(*[]uint32)(unsafe.Pointer(&v0)),
				*(*uint32)(unsafe.Pointer(&c)),
				*(*[]uint32)(unsafe.Pointer(&vOut)),
			)
			return

		case uint64:
			scalarMulAddAssignUint64AVX2(
				*(*[]uint64)(unsafe.Pointer(&v0)),
				*(*uint64)(unsafe.Pointer(&c)),
				*(*[]uint64)(unsafe.Pointer(&vOut)),
			)
			return
		}
	}

	M := (len(vOut) >> 3) << 3

	for i := 0; i < M; i += 8 {
		w0 := (*[8]T)(unsafe.Pointer(&v0[i]))
		wOut := (*[8]T)(unsafe.Pointer(&vOut[i]))

		wOut[0] += c * w0[0]
		wOut[1] += c * w0[1]
		wOut[2] += c * w0[2]
		wOut[3] += c * w0[3]

		wOut[4] += c * w0[4]
		wOut[5] += c * w0[5]
		wOut[6] += c * w0[6]
		wOut[7] += c * w0[7]
	}

	for i := M; i < len(vOut); i++ {
		vOut[i] += c * v0[i]
	}
}

// ScalarMulSubAssign computes vOut -= c * v0.
func ScalarMulSubAssign[T num.Number](v0 []T, c T, vOut []T) {
	if cpu.X86.HasAVX2 && cpu.X86.HasFMA {
		var z T
		switch any(z).(type) {
		case uint32:
			scalarMulSubAssignUint32AVX2(
				*(*[]uint32)(unsafe.Pointer(&v0)),
				*(*uint32)(unsafe.Pointer(&c)),
				*(*[]uint32)(unsafe.Pointer(&vOut)),
			)
			return

		case uint64:
			scalarMulSubAssignUint64AVX2(
				*(*[]uint64)(unsafe.Pointer(&v0)),
				*(*uint64)(unsafe.Pointer(&c)),
				*(*[]uint64)(unsafe.Pointer(&vOut)),
			)
			return
		}
	}

	M := (len(vOut) >> 3) << 3

	for i := 0; i < M; i += 8 {
		w0 := (*[8]T)(unsafe.Pointer(&v0[i]))
		wOut := (*[8]T)(unsafe.Pointer(&vOut[i]))

		wOut[0] -= c * w0[0]
		wOut[1] -= c * w0[1]
		wOut[2] -= c * w0[2]
		wOut[3] -= c * w0[3]

		wOut[4] -= c * w0[4]
		wOut[5] -= c * w0[5]
		wOut[6] -= c * w0[6]
		wOut[7] -= c * w0[7]
	}

	for i := M; i < len(vOut); i++ {
		vOut[i] -= c * v0[i]
	}
}

// ElementWiseMulAssign computes vOut = v0 * v1, where * is an elementwise multiplication.
func ElementWiseMulAssign[T num.Number](v0, v1, vOut []T) {
	if cpu.X86.HasAVX2 && cpu.X86.HasFMA {
		var z T
		switch any(z).(type) {
		case uint32:
			elementWiseMulAssignUint32AVX2(
				*(*[]uint32)(unsafe.Pointer(&v0)),
				*(*[]uint32)(unsafe.Pointer(&v1)),
				*(*[]uint32)(unsafe.Pointer(&vOut)),
			)
			return

		case uint64:
			elementWiseMulAssignUint64AVX2(
				*(*[]uint64)(unsafe.Pointer(&v0)),
				*(*[]uint64)(unsafe.Pointer(&v1)),
				*(*[]uint64)(unsafe.Pointer(&vOut)),
			)
			return
		}
	}

	M := (len(vOut) >> 3) << 3

	for i := 0; i < M; i += 8 {
		w0 := (*[8]T)(unsafe.Pointer(&v0[i]))
		w1 := (*[8]T)(unsafe.Pointer(&v1[i]))
		wOut := (*[8]T)(unsafe.Pointer(&vOut[i]))

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

// ElementWiseMulAddAssign computes vOut += v0 * v1, where * is an elementwise multiplication.
func ElementWiseMulAddAssign[T num.Number](v0, v1, vOut []T) {
	if cpu.X86.HasAVX2 && cpu.X86.HasFMA {
		var z T
		switch any(z).(type) {
		case uint32:
			elementWiseMulAddAssignUint32AVX2(
				*(*[]uint32)(unsafe.Pointer(&v0)),
				*(*[]uint32)(unsafe.Pointer(&v1)),
				*(*[]uint32)(unsafe.Pointer(&vOut)),
			)
			return

		case uint64:
			elementWiseMulAddAssignUint64AVX2(
				*(*[]uint64)(unsafe.Pointer(&v0)),
				*(*[]uint64)(unsafe.Pointer(&v1)),
				*(*[]uint64)(unsafe.Pointer(&vOut)),
			)
			return
		}
	}

	M := (len(vOut) >> 3) << 3

	for i := 0; i < M; i += 8 {
		w0 := (*[8]T)(unsafe.Pointer(&v0[i]))
		w1 := (*[8]T)(unsafe.Pointer(&v1[i]))
		wOut := (*[8]T)(unsafe.Pointer(&vOut[i]))

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

// ElementWiseMulSubAssign computes vOut -= v0 * v1, where * is an elementwise multiplication.
func ElementWiseMulSubAssign[T num.Number](v0, v1, vOut []T) {
	if cpu.X86.HasAVX2 && cpu.X86.HasFMA {
		var z T
		switch any(z).(type) {
		case uint32:
			elementWiseMulSubAssignUint32AVX2(
				*(*[]uint32)(unsafe.Pointer(&v0)),
				*(*[]uint32)(unsafe.Pointer(&v1)),
				*(*[]uint32)(unsafe.Pointer(&vOut)),
			)
			return

		case uint64:
			elementWiseMulSubAssignUint64AVX2(
				*(*[]uint64)(unsafe.Pointer(&v0)),
				*(*[]uint64)(unsafe.Pointer(&v1)),
				*(*[]uint64)(unsafe.Pointer(&vOut)),
			)
			return
		}
	}

	M := (len(vOut) >> 3) << 3

	for i := 0; i < M; i += 8 {
		w0 := (*[8]T)(unsafe.Pointer(&v0[i]))
		w1 := (*[8]T)(unsafe.Pointer(&v1[i]))
		wOut := (*[8]T)(unsafe.Pointer(&vOut[i]))

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
